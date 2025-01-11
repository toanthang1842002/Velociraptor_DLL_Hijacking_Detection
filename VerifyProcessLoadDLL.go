package DLL_Hijacking_Detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Velocidex/ordereddict"
	_ "github.com/go-sql-driver/mysql"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
	"www.velocidex.com/golang/vfilter/types"
)

type VerifyProcessLoadDLLArgs struct {
	PID            int64  `vfilter:"optional,field=pid,doc=Process ID to verify"`
	ScanPath       string `vfilter:"optional,field=scan_path,doc=Path to scan for DLLs"`
	SigcheckPath   string `vfilter:"required,field=sigcheck_path,doc=Path to sigcheck.exe"`
	VerifyToolPath string `vfilter:"required,field=verify_tool_path,doc=Path to verify_dir.exe"`
	HostNameDB     string `vfilter:"required,field=host_name_db,doc=Host name of DLL database"`
	WhiteListPath  string `vfilter:"optional,field=white_list_path,doc=Path to white list file"`
}

type DllAnalysisResult struct {
	ID             int           `json:"id"`
	DllInfos       DllInfo       `json:"process_info"`
	SignatureInfos SignatureInfo `json:"signature_info"`
	FinalResult    string        `json:"final_result"`
	Point          int           `json:"point"`
}

// Initialize connection to MySQL database#######################################################################
var db *sql.DB

func InitializeDB(host string) error {
	port := "3306"
	user := "velociraptor"
	password := "T@iga184"
	database := "dll_database"
	var err error
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, password, host, port, database)

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("không thể kết nối đến database: %v", err)
	}
	return nil
}

//Function support ###########################################################################################

func toString(value interface{}, ok bool) string {
	if !ok || value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}

func dllPathExists(analysisResults []DllAnalysisResult, dllPath string) int {
	for i, result := range analysisResults {
		if result.DllInfos.DllPath == dllPath {
			return i
		}
	}
	return -1
}

func isDLLLegitimate(db *sql.DB, hashSHA1 string) int {
	query_hash := fmt.Sprintf("SELECT * FROM legitimate_dll where sha1 = '%s'", hashSHA1)

	// Execute query
	rows, err := db.Query(query_hash)
	if err != nil {
		return -1
	}
	defer rows.Close()
	if rows.Next() {
		return 0
	}
	return 1
}

func getWhiteListPath(whiteListPath string) []string {
	parts := strings.Split(whiteListPath, ";")
	for i, part := range parts {
		part = strings.ToLower(part)
		parts[i] = strings.ReplaceAll(part, `\\`, `\`)
	}
	return parts
}

func pathInWhitelist(path string, Whitelist []string) bool {
	for _, whitelistPath := range Whitelist {
		if strings.HasPrefix(strings.ToLower(path), whitelistPath) {
			return true
		}
	}
	return false
}

//Create plugin #############################################################################################################

type VerifyProcessLoadDLLPlugin struct{}

func (self VerifyProcessLoadDLLPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "verify_process_load_dll_plugin",
		Doc:     "Check running processes for DLLs that may be susceptible to DLL hijacking",
		ArgType: type_map.AddType(scope, &SigCheckArgs{}),
	}
}

func (self VerifyProcessLoadDLLPlugin) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan types.Row {

	output_chan := make(chan types.Row)
	arg := &VerifyProcessLoadDLLArgs{}
	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor("check_dll_sideload", args)()

		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("check_dll_sideload: %s", err.Error())
			return
		}

		scope.Log("%v", arg.ScanPath)

		// Connect to database
		if err = InitializeDB(arg.HostNameDB); err != nil {
			scope.Log("Lỗi kết nối DB: %v\n", err)
			return
		}

		scope.Log("Connect to database successfully")

		// get whitelist path
		whitelistPath := getWhiteListPath(arg.WhiteListPath)
		scope.Log("White list path: %v", whitelistPath)

		// Get all process load DLL
		processDllPlugin := &ProcessDllPlugin{}

		scope.Log("start get all process load DLL with PID: %d", arg.PID)
		processDllArgs := ordereddict.NewDict().
			Set("pid", arg.PID)

		var jsonFilePath string
		for row := range processDllPlugin.Call(ctx, scope, processDllArgs) {
			if dict, ok := row.(*ordereddict.Dict); ok {
				if path, ok := dict.Get("result_file"); ok {
					jsonFilePath = path.(string)
				}
			}
		}

		scope.Log("Get all Process load DLL successfully ><")

		//jsonFilePath := "C:\\Users\\Savage\\Downloads\\velociraptor-master\\velociraptor-master\\vql\\hunting-sideload\\DLLList_1735739229477421900.json"
		if jsonFilePath == "" {
			scope.Log("Failed to get JSON file path from process_dll_plugin")
			return
		}
		jsonData, err := ioutil.ReadFile(jsonFilePath)
		if err != nil {
			scope.Log("Failed to read JSON file: %s", err.Error())
			return
		}

		var dllInfos []DllInfo
		decoder := json.NewDecoder(strings.NewReader(string(jsonData)))

		_, err = decoder.Token()
		if err != nil {
			scope.Log("Error reading array start token: %v", err)
			return
		}

		for decoder.More() {
			var dllInfo DllInfo
			if err := decoder.Decode(&dllInfo); err != nil {
				scope.Log("Error decoding JSON entry: %s", err.Error())
				continue
			}
			dllInfos = append(dllInfos, dllInfo)
		}

		// Create file to store data to analyze

		currentDir, err := os.Getwd()
		if err != nil {
			scope.Log("Failed to get current directory: %s", err.Error())
			return
		}

		fileNameAnalyze := fmt.Sprintf("dataToAnalyzePath_%d.json", time.Now().UnixNano())
		dataToAnalyzePath := filepath.Join(currentDir, fileNameAnalyze)
		resultDataToAnalyzePath := filepath.Join(currentDir, fmt.Sprintf("result_%s", fileNameAnalyze))

		dataToAnalyze, err := os.Create(dataToAnalyzePath)
		if err != nil {
			scope.Log("Failed to create hash file: %s", err.Error())
			return
		}
		defer dataToAnalyze.Close()

		resultDataToAnalyze, err := os.Create(resultDataToAnalyzePath)
		if err != nil {
			scope.Log("Failed to create hash file: %s", err.Error())
			return
		}
		defer resultDataToAnalyze.Close()

		encoder := json.NewEncoder(dataToAnalyze)
		encoder.SetIndent("", "  ")

		var analysisResults []DllAnalysisResult

		// Process each DLL found
		for i, dllInfo := range dllInfos {
			if arg.ScanPath != "" && !strings.HasPrefix(strings.ToLower(dllInfo.DllPath), strings.ToLower(arg.ScanPath)) {
				continue
			}

			if arg.WhiteListPath != "" && pathInWhitelist(dllInfo.DllPath, whitelistPath) {
				continue
			}

			var signatureInfo SignatureInfo
			pos := dllPathExists(analysisResults, dllInfo.DllPath)
			if pos != -1 {
				signatureInfo = analysisResults[pos].SignatureInfos
			} else {
				filesign_args := ordereddict.NewDict().
					Set("file_path", dllInfo.DllPath)

				if arg.SigcheckPath != "" {
					filesign_args.Set("sigcheck_path", arg.SigcheckPath)
				}

				sigcheck := &SigCheckPlugin{}
				rows := []types.Row{}

				for row := range sigcheck.Call(ctx, scope, filesign_args) {
					rows = append(rows, row)
				}

				for _, result := range rows {
					dict := result.(*ordereddict.Dict)
					signatureInfo = SignatureInfo{
						Name:        toString(dict.Get("name")),
						Verified:    toString(dict.Get("verified")),
						Publisher:   toString(dict.Get("publisher")),
						Company:     toString(dict.Get("company")),
						Description: toString(dict.Get("description")),
						ProductName: toString(dict.Get("product_name")),
						FileVersion: toString(dict.Get("file_version")),
						FileDate:    toString(dict.Get("file_date")),
						MD5:         toString(dict.Get("md5")),
						SHA1:        toString(dict.Get("sha1")),
						PESHA1:      toString(dict.Get("pe_sha1")),
					}
				}
			}
			// Create DllAnalysisResult for each DLL
			PointDB := isDLLLegitimate(db, signatureInfo.SHA1)
			if PointDB == -1 {
				scope.Log("Failed to query database")
				return
			}

			scope.Log("Result after query DB: %d", PointDB)

			analysisResult := DllAnalysisResult{
				ID:             i,
				DllInfos:       dllInfo,
				SignatureInfos: signatureInfo,
				FinalResult:    "",
				Point:          PointDB,
			}
			analysisResults = append(analysisResults, analysisResult)
		}
		db.Close()
		err = encoder.Encode(analysisResults)
		if err != nil {
			scope.Log("Failed to encode and write JSON: %v", err)
			return
		}

		// execute tools verify.exe

		cmd := exec.CommandContext(ctx, arg.VerifyToolPath, "-dp", dataToAnalyzePath, "-o", resultDataToAnalyzePath)
		scope.Log("execute command verify_dir.exe")
		output, _ := cmd.CombinedOutput()
		scope.Log("output after execute command verify_dir.exe: %s", output)

		// Read result file
		var finalAnalysisResults []DllAnalysisResult
		jsonData, err = ioutil.ReadFile(resultDataToAnalyzePath)
		if err != nil {
			scope.Log("Failed to read JSON file: %s", err.Error())
			return
		}

		decoder = json.NewDecoder(strings.NewReader(string(jsonData)))

		_, err = decoder.Token()
		if err != nil {
			scope.Log("Error reading array start token: %v", err)
			return
		}

		for decoder.More() {
			var AnalysisResult DllAnalysisResult
			if err := decoder.Decode(&AnalysisResult); err != nil {
				scope.Log("Error decoding JSON entry: %s", err.Error())
				continue
			}
			finalAnalysisResults = append(finalAnalysisResults, AnalysisResult)
		}
		for _, finalAnalysisResult := range finalAnalysisResults {
			select {
			case <-ctx.Done():
				return
			case output_chan <- ordereddict.NewDict().
				Set("process_path", finalAnalysisResult.DllInfos.ProcessPath).
				Set("parent_path", finalAnalysisResult.DllInfos.ParentPath).
				Set("dll_path", finalAnalysisResult.DllInfos.DllPath).
				Set("size", finalAnalysisResult.DllInfos.Size).
				Set("signature", finalAnalysisResult.SignatureInfos.Verified).
				Set("sha1", finalAnalysisResult.SignatureInfos.SHA1).
				Set("final_result", finalAnalysisResult.FinalResult).
				Set("point", finalAnalysisResult.Point):
			}

		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&VerifyProcessLoadDLLPlugin{})
}
