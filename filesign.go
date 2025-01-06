package DLL_Hijacking_Detection

import (
	"context"
	_ "encoding/json"
	"os/exec"
	"strings"

	"www.velocidex.com/golang/vfilter/arg_parser"

	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/types"
)

type SigCheckPlugin struct{}

func (self SigCheckPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "check_signature",
		Doc:     "Check file signature using Sysinternals Sigcheck",
		ArgType: type_map.AddType(scope, &SigCheckArgs{}),
	}
}

type SigCheckArgs struct {
	FilePath     string `vfilter:"required,field=file_path,doc=Path to the file to check"`
	SigcheckPath string `vfilter:"optional,field=sigcheck_path,doc=Path to sigcheck.exe"`
}

type SignatureInfo struct {
	Name        string `json:"name"`
	Verified    string `json:"verified"`
	Publisher   string `json:"publisher"`
	Company     string `json:"company"`
	Description string `json:"description"`
	ProductName string `json:"product_name"`
	FileVersion string `json:"file_version"`
	FileDate    string `json:"file_date"`
	MD5         string `json:"md5"`
	SHA1        string `json:"sha1"`
	PESHA1      string `json:"pe_sha1"`
}

func (self SigCheckPlugin) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan types.Row {

	output_chan := make(chan types.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor("check_signature", args)()

		arg := &SigCheckArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("check_signature: %s", err.Error())
			return
		}

		sigcheckPath := arg.SigcheckPath
		if sigcheckPath == "" {
			sigcheckPath = "C:\\Program Files\\Velociraptor\\Tools\\sigcheck64.exe"
		}
		filePath := arg.FilePath

		// Create the command to run sigcheck with JSON output
		cmd := exec.CommandContext(ctx, sigcheckPath, "-nobanner", "-accepteula", "-h", filePath)
		scope.Log("execute command sigcheck: %s", filePath)
		output, _ := cmd.CombinedOutput()
		lines := strings.Split(string(output), "\n")
		output_parse := &SignatureInfo{}
		var signatureInfos []SignatureInfo
		for i, line := range lines {
			line = strings.TrimSpace(line)
			isLastLine := i == len(lines)-1
			if strings.HasPrefix(strings.ToLower(line), "c:") && output_parse.MD5 != "" {
				signatureInfos = append(signatureInfos, *output_parse)
				output_parse = &SignatureInfo{}
				scope.Log("Initialized output_parse: %s", output_parse.Name)
			}
			if isLastLine {
				signatureInfos = append(signatureInfos, *output_parse)
			}
			if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					key := strings.ToLower(strings.TrimSpace(parts[0]))
					value := strings.TrimSpace(strings.Join(parts[1:], ":"))

					switch key {
					case "c":
						output_parse.Name = strings.TrimSpace(strings.TrimSuffix(line, ":"))
					case "verified":
						output_parse.Verified = value
					case "publisher":
						output_parse.Publisher = value
					case "company":
						output_parse.Company = value
					case "description":
						output_parse.Description = value
					case "product":
						output_parse.ProductName = value
					case "file version":
						output_parse.FileVersion = value
					case "file date":
						output_parse.FileDate = value
					case "link date":
						output_parse.FileDate = value
					case "md5":
						output_parse.MD5 = value
					case "sha1":
						output_parse.SHA1 = value
					case "pesha1":
						output_parse.PESHA1 = value
					}
				}
			}
		}
		for _, info := range signatureInfos {
			select {
			case <-ctx.Done():
				return
			case output_chan <- ordereddict.NewDict().
				Set("name", info.Name).
				Set("verified", info.Verified).
				Set("publisher", info.Publisher).
				Set("company", info.Company).
				Set("description", info.Description).
				Set("product_name", info.ProductName).
				Set("file_version", info.FileVersion).
				Set("file_date", info.FileDate).
				Set("md5", info.MD5).
				Set("sha1", info.SHA1).
				Set("pe_sha1", info.PESHA1):
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&SigCheckPlugin{})
}
