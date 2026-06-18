package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"go.uber.org/zap"

	"github.com/Ammar777782439/scanconverter/pkg/converter"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

func main() {
	toolName := flag.String("tool", "", "Name of the tool (e.g., nmap, nuclei, masscan)")
	filePath := flag.String("file", "", "Path to the scan output file to parse")
	flag.Parse()

	if *toolName == "" || *filePath == "" {
		fmt.Println("Usage: go run main.go -tool <tool_name> -file <path_to_file>")
		fmt.Println("Example: go run main.go -tool nmap -file scan.xml")
		os.Exit(1)
	}

	// 1. Initialize Logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("logger init: %v", err)
	}
	defer logger.Sync()

	// 2. Initialize Registry & Load Schemas
	reg := schema.NewRegistry(logger)
	if err := reg.LoadDir("schemas"); err != nil {
		logger.Warn("Failed to load schemas. Continuing anyway...", zap.Error(err))
	} else {
		logger.Info("Schemas loaded successfully")
	}

	// 3. Read the scan output file
	raw, err := os.ReadFile(*filePath)
	if err != nil {
		logger.Fatal("Failed to read file", zap.Error(err))
	}

	// 4. Initialize Converter
	conv := converter.NewConverter(reg, converter.WithLogger(logger))

	// 5. Convert the file!
	logger.Info("Starting conversion...", zap.String("tool", *toolName), zap.String("file", *filePath))
	result, err := conv.Convert(*toolName, raw, "example-target.com", "job-12345")
	if err != nil {
		logger.Fatal("Conversion failed", zap.Error(err))
	}

	// 6. Print the unified summary and JSON output
	logger.Info("Conversion complete!", zap.Int("findings_count", len(result.Findings)))
	
	jsonOutput, err := result.ToJSON()
	if err != nil {
		logger.Fatal("Failed to convert result to JSON", zap.Error(err))
	}

	fmt.Println("\n--- Normalized Output ---")
	fmt.Println(string(jsonOutput))
}
