package DLL_Hijacking_Detection

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Velocidex/ordereddict"
	"math"
	"os"
	"path/filepath"
	_ "path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

var (
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procGetModuleFileNameExW = psapi.NewProc("GetModuleFileNameExW")
	getModuleInformation     = psapi.NewProc("GetModuleInformation")
)

type DllInfo struct {
	ProcessPath string `json:"process_path"`
	ParentPath  string `json:"parent_path"`
	DllPath     string `json:"dll_path"`
	Size        uint32 `json:"size"`
	Result      string `json:"result"`
}

type CommonElement struct {
	DllName     string
	AbsPath     string
	Size        uint32
	CountCommon int
}

type StandardElement struct {
	DllName string
	AbsPath string
	SizeMin uint32
	SizeMax uint32
}

type PluginArgs struct {
	PID int64 `vfilter:"optional,field=pid,doc=A process ID to list DLLs from. If not provided, list DLLs from all processes."`
}

//############################ Get info process #################################
// GetModuleFileNameEx retrieves the module name of a specific DLL

func getModuleFileNameEx(procHandle windows.Handle, moduleHandle windows.Handle, buffer *uint16, size uint32) uint32 {
	ret, _, _ := procGetModuleFileNameExW.Call(
		uintptr(procHandle),
		uintptr(moduleHandle),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(size),
	)
	return uint32(ret)
}

func getProcessPath(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var pathBuf [windows.MAX_PATH]uint16
	size := uint32(len(pathBuf))
	if err := windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &size); err == nil {
		return syscall.UTF16ToString(pathBuf[:size])
	}
	return ""
}

func getDLLSize(processHandle windows.Handle, module windows.Handle) (uint32, error) {
	var modInfo struct {
		BaseOfDll   uintptr
		SizeOfImage uint32
		EntryPoint  uintptr
	}
	ret, _, err := getModuleInformation.Call(
		uintptr(processHandle),
		uintptr(module),
		uintptr(unsafe.Pointer(&modInfo)),
		unsafe.Sizeof(modInfo),
	)
	if ret == 0 {
		return 0, err
	}
	return modInfo.SizeOfImage, nil
}

//############################ Check legitimate by Name and Path #################################

func RemoveOutliers(data []int, threshold float64) []int {
	mean := 0.0
	for _, v := range data {
		mean += float64(v)
	}
	mean /= float64(len(data))

	variance := 0.0
	for _, v := range data {
		variance += math.Pow(float64(v)-mean, 2)
	}
	stdDev := math.Sqrt(variance / float64(len(data)))

	filtered := []int{}
	for _, v := range data {
		if float64(v) >= mean-threshold*stdDev && float64(v) <= mean+threshold*stdDev {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func getCommonElement(commonElements []CommonElement) StandardElement {
	standardElement := StandardElement{}
	standardElement.DllName = commonElements[0].DllName
	mostCommon := ""
	maxCount := 0
	sizes := []int{}
	for _, commonElement := range commonElements {
		if commonElement.CountCommon > maxCount {
			mostCommon = commonElement.AbsPath
			maxCount = commonElement.CountCommon
		}
		sizes = append(sizes, int(commonElement.Size))
	}
	filteredSizes := RemoveOutliers(sizes, 2.0)

	minSize := math.MaxInt32
	maxSize := math.MinInt32

	for _, size := range filteredSizes {
		if size < minSize {
			minSize = size
		}
		if size > maxSize {
			maxSize = size
		}
	}

	standardElement.SizeMin = uint32(minSize)
	standardElement.SizeMax = uint32(maxSize)
	standardElement.AbsPath = mostCommon
	return standardElement
}

func checkSuspicious(info DllInfo, standardElements []StandardElement) string {
	dllName := filepath.Base(info.DllPath)
	for _, standardElement := range standardElements {
		if strings.ToLower(standardElement.DllName) == strings.ToLower(dllName) {
			if info.Size < standardElement.SizeMin || info.Size > standardElement.SizeMax || strings.ToLower(info.DllPath) != standardElement.AbsPath {
				return "Suspicious"
			}
		}
	}
	return "Legitimate"
}

type ProcessDllPlugin struct{}

func (plugin ProcessDllPlugin) Call(ctx context.Context, scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)
	arg := &PluginArgs{}

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor("dll_list", args)()

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg); err != nil {
			scope.Log("Failed to parse arguments: %v", err)
			return
		}

		resultFile := fmt.Sprintf("DLLList_%d.json", time.Now().UnixNano())
		file, err := os.Create(resultFile)
		if err != nil {
			scope.Log("Failed to create result file: %v", err)
			return
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")

		handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, uint32(arg.PID))
		if err != nil {
			scope.Log("Failed to create snapshot: %v", err)
			return
		}
		defer windows.CloseHandle(handle)

		var entry windows.ProcessEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		infos := []DllInfo{}
		commonElements := make(map[CommonElement]int)

		for err = windows.Process32First(handle, &entry); err == nil; err = windows.Process32Next(handle, &entry) {

			processPath := getProcessPath(entry.ProcessID)
			parentPath := getProcessPath(entry.ParentProcessID)

			procHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, entry.ProcessID)
			if err != nil {
				continue
			}
			defer windows.CloseHandle(procHandle)

			var modules [1024]windows.Handle
			var needed uint32
			if err := windows.EnumProcessModulesEx(procHandle, &modules[0], uint32(len(modules))*uint32(unsafe.Sizeof(modules[0])), &needed, windows.LIST_MODULES_ALL); err != nil {
				continue
			}

			count := needed / uint32(unsafe.Sizeof(modules[0]))

			for i := 0; i < int(count); i++ {
				var DllPathBuf [windows.MAX_PATH]uint16
				length := getModuleFileNameEx(procHandle, modules[i], &DllPathBuf[0], windows.MAX_PATH)
				if length == 0 {
					continue
				}
				DllPath := syscall.UTF16ToString(DllPathBuf[:length])

				size, _ := getDLLSize(procHandle, modules[i])

				infos = append(infos, DllInfo{
					ProcessPath: processPath,
					ParentPath:  parentPath,
					DllPath:     DllPath,
					Size:        size,
					Result:      "Unknown",
				})

				DllName := filepath.Base(DllPath)
				AbsPath, _ := filepath.Abs(DllPath)
				commonElements[CommonElement{DllName: strings.ToLower(DllName), AbsPath: strings.ToLower(AbsPath), Size: size, CountCommon: 0}]++

			}
		}

		groupedCommonElements := make(map[string][]CommonElement)
		standardElements := []StandardElement{}

		for commonElement, _ := range commonElements {
			commonElement.CountCommon = commonElements[commonElement]
			groupedCommonElements[commonElement.DllName] = append(groupedCommonElements[commonElement.DllName], commonElement)
		}

		for _, commonElement := range groupedCommonElements {
			standardElements = append(standardElements, getCommonElement(commonElement))
		}

		finalInfos := []DllInfo{}

		for _, info := range infos {
			info.Result = checkSuspicious(info, standardElements)
			finalInfos = append(finalInfos, info)
		}

		if err := encoder.Encode(finalInfos); err != nil {
			scope.Log("Failed to write JSON: %v", err)
		}

		currentDir, err := os.Getwd()
		select {
		case <-ctx.Done():
			return
		case output_chan <- ordereddict.NewDict().Set("result_file", filepath.Join(currentDir, resultFile)):
		}

	}()
	return output_chan
}

func (plugin ProcessDllPlugin) Info(scope vfilter.Scope, typeMap *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "dll_list",
		Doc:     "List all DLLs loaded by processes with detailed information.",
		ArgType: typeMap.AddType(scope, &PluginArgs{}),
	}
}

func init() {
	vql_subsystem.RegisterPlugin(&ProcessDllPlugin{})
}
