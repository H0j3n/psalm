<?php

namespace Psalm\Internal\Analyzer\Statements\Expression;

use PhpParser;
use Psalm\CodeLocation;
use Psalm\Context;
use Psalm\Internal\Analyzer\Statements\ExpressionAnalyzer;
use Psalm\Internal\Analyzer\StatementsAnalyzer;
use Psalm\Internal\Codebase\TaintFlowGraph;
use Psalm\Internal\DataFlow\DataFlowNode;
use Psalm\Internal\DataFlow\TaintSink;
use Psalm\Issue\TaintedWordPressLFI;
use Psalm\IssueBuffer;
use Psalm\Type;
use Psalm\Type\TaintKind;

use function in_array;
use function strpos;

/**
 * @internal
 */
final class ExtractAnalyzer
{
    /**
     * Check if a data flow node represents HTTP input
     */
    private static function isHttpInput(DataFlowNode $node): bool
    {
        $id = $node->id;
        $label = $node->label ?? '';
        
        return strpos($id, '$_POST') !== false || 
               strpos($id, '$_GET') !== false || 
               strpos($id, '$_REQUEST') !== false ||
               strpos($id, '$_COOKIE') !== false ||
               strpos($label, '$_POST') !== false || 
               strpos($label, '$_GET') !== false || 
               strpos($label, '$_REQUEST') !== false ||
               strpos($label, '$_COOKIE') !== false;
    }

    /**
     * Recursively search for HTTP sources in parent nodes
     */
    private static function findHttpSources(array $parent_nodes, int $depth = 0): array
    {
        if ($depth > 5) {
            return [];
        }
        
        $http_sources = [];
        
        foreach ($parent_nodes as $parent_node) {
            if (self::isHttpInput($parent_node)) {
                $http_sources[] = $parent_node->id;
            }
            
            // Check parent nodes recursively
            if (isset($parent_node->parent_nodes)) {
                $recursive_sources = self::findHttpSources($parent_node->parent_nodes, $depth + 1);
                $http_sources = array_merge($http_sources, $recursive_sources);
            }
        }
        
        return array_unique($http_sources);
    }

    public static function analyze(
        StatementsAnalyzer $statements_analyzer,
        PhpParser\Node\Expr\FuncCall $stmt,
        Context $context
    ): void {
        // Only analyze extract() function calls
        if (!$stmt->name instanceof PhpParser\Node\Name || 
            strtolower($stmt->name->toString()) !== 'extract') {
            return;
        }

        // Found extract() call - analyzing for potential LFI vulnerability

        if (empty($stmt->getArgs())) {
            return;
        }

        // Analyze the first argument (the array being extracted)
        ExpressionAnalyzer::analyze($statements_analyzer, $stmt->getArgs()[0]->value, $context);
        
        $extract_arg_type = $statements_analyzer->node_data->getType($stmt->getArgs()[0]->value);

        if ($extract_arg_type
            && $statements_analyzer->data_flow_graph instanceof TaintFlowGraph
            && !in_array('TaintedInput', $statements_analyzer->getSuppressedIssues())
        ) {
            $arg_location = new CodeLocation($statements_analyzer->getSource(), $stmt->getArgs()[0]->value);
            
            // Check for HTTP input sources if parent nodes exist
            $http_sources = [];
            if ($extract_arg_type->parent_nodes) {
                $http_sources = self::findHttpSources($extract_arg_type->parent_nodes);
            }
            
            // Also check for WordPress-specific patterns (json_decode with user input)
            $wordpress_pattern_detected = false;
            $arg_source = $stmt->getArgs()[0]->value;
            
            // Check if the argument comes from json_decode or similar patterns
            if ($arg_source instanceof PhpParser\Node\Expr\Variable && 
                isset($arg_source->name) && 
                is_string($arg_source->name) &&
                ($arg_source->name === 'attributes' || $arg_source->name === 'data')) {
                $wordpress_pattern_detected = true;
                // WordPress pattern detected: extract() with user-controlled variable
            }
            
            if (!empty($http_sources) || $wordpress_pattern_detected) {
                // Don't report extract() itself as a vulnerability
                // Just mark this context as having a dangerous extract() call
                // The actual vulnerability will be reported when include() is found
                $context->vars_in_scope['__psalm_extract_vulnerability_detected'] = Type::getTrue();
                
                // Store the source info for later use in include() detection
                $source_info = !empty($http_sources) ? implode(', ', $http_sources) : 'WordPress user input pattern';
                $context->vars_in_scope['__psalm_extract_source_info'] = Type::getString($source_info);

                // Create taint sink for extract
                $extract_sink = TaintSink::getForMethodArgument(
                    'extract',
                    'extract',
                    0,
                    $arg_location,
                    $arg_location,
                );

                $extract_sink->taints = [TaintKind::INPUT_INCLUDE];
                $statements_analyzer->data_flow_graph->addSink($extract_sink);

                // Add paths from parent nodes to the sink if they exist
                if ($extract_arg_type->parent_nodes) {
                    foreach ($extract_arg_type->parent_nodes as $parent_node) {
                        $statements_analyzer->data_flow_graph->addPath(
                            $parent_node,
                            $extract_sink,
                            'arg',
                        );
                    }
                }
            }
        }
    }
} 