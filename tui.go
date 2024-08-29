package main

import (
	"fmt"
	"log"
	"sort"

	"github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

type UI struct {
	successGraph       *widgets.Plot
	failureGraph       *widgets.Plot
	contextSwitchGraph *widgets.Plot
	infoList           *widgets.List
}

func InitUI() (*UI, error) {
	if err := termui.Init(); err != nil {
		return nil, err
	}

	ui := &UI{
		successGraph:       widgets.NewPlot(),
		failureGraph:       widgets.NewPlot(),
		contextSwitchGraph: widgets.NewPlot(),
		infoList:           widgets.NewList(),
	}

	// Initialize the graphs and list (set titles, rectangles, etc.)
	// Initialise termui
	if err := termui.Init(); err != nil {
		log.Fatalf("failed to initialise termui: %v", err)
	}

	// Create graphs with adjusted width
	ui.successGraph = widgets.NewPlot()
	ui.successGraph.Title = "Successful Syscalls"
	ui.successGraph.Data = make([][]float64, 1)
	ui.successGraph.SetRect(0, 0, 50, 12) // Width: 50

	ui.failureGraph = widgets.NewPlot()
	ui.failureGraph.Title = "Failed Syscalls"
	ui.failureGraph.Data = make([][]float64, 1)
	ui.failureGraph.SetRect(0, 12, 50, 24) // Width: 50

	ui.contextSwitchGraph = widgets.NewPlot()
	ui.contextSwitchGraph.Title = "Context Switches"
	ui.contextSwitchGraph.Data = make([][]float64, 1)
	ui.contextSwitchGraph.SetRect(50, 0, 100, 12) // Width: 50

	ui.successGraph.Data[0] = make([]float64, windowSize)
	ui.failureGraph.Data[0] = make([]float64, windowSize)
	ui.contextSwitchGraph.Data[0] = make([]float64, windowSize)

	// Create a list widget to display the last change in success and failure counts
	ui.infoList = widgets.NewList()
	ui.infoList.Title = "Last Change in Syscall Counts"
	ui.infoList.SetRect(50, 12, 100, 24) // Position to the right of the graphs

	formatInfoList(make(map[string][2]uint64))

	termui.Render(ui.successGraph, ui.failureGraph, ui.contextSwitchGraph, ui.infoList)

	return ui, nil
}

func ShutdownUI() {
	termui.Close()
}

func (ui *UI) Update(successArray, failureArray, contextSwitchArray []float64, currentSyscallCounts map[string][2]uint64) {
	copy(ui.successGraph.Data[0], successArray)
	copy(ui.failureGraph.Data[0], failureArray)
	copy(ui.contextSwitchGraph.Data[0], contextSwitchArray)

	ui.infoList.Rows = formatInfoList(currentSyscallCounts)

	termui.Render(ui.successGraph, ui.failureGraph, ui.contextSwitchGraph, ui.infoList)
}

func (ui *UI) Run() {
	uiEvents := termui.PollEvents()
	for {
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return
		}
	}
}

func formatInfoList(currentSyscallCounts map[string][2]uint64) []string {
	var formattedRows []string

	keys := make([]string, 0, len(currentSyscallCounts))
	for k := range currentSyscallCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Stable sort by syscall name

	formattedRows = append(formattedRows, "")
	for _, syscall := range keys {
		counts := currentSyscallCounts[syscall]
		lastCounts := lastSyscallCounts[syscall]
		successDiff := counts[0] - lastCounts[0]
		failureDiff := counts[1] - lastCounts[1]
		formattedRows = append(formattedRows, fmt.Sprintf("[%s](fg:yellow) Success: [%d](fg:green) Failure: [%d](fg:red)", syscall, successDiff, failureDiff))
		lastSyscallCounts[syscall] = counts
	}

	return formattedRows
}
