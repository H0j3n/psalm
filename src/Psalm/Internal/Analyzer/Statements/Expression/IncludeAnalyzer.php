<?php

namespace Psalm\Internal\Analyzer\Statements\Expression;

use AssertionError;
use PhpParser;
use Psalm\CodeLocation;
use Psalm\Config;
use Psalm\Context;
use Psalm\Exception\FileIncludeException;
use Psalm\Exception\UnpreparedAnalysisException;
use Psalm\Internal\Analyzer\FileAnalyzer;
use Psalm\Internal\Analyzer\Statements\ExpressionAnalyzer;
use Psalm\Internal\Analyzer\StatementsAnalyzer;
use Psalm\Internal\Codebase\TaintFlowGraph;
use Psalm\Internal\DataFlow\DataFlowNode;
use Psalm\Internal\DataFlow\TaintSink;
use Psalm\Internal\Provider\NodeDataProvider;
use Psalm\Issue\MissingFile;
use Psalm\Issue\TaintedInclude;
use Psalm\Issue\TaintedWordPressLFI;
use Psalm\Issue\UnresolvableInclude;
use Psalm\IssueBuffer;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Type\TaintKind;
use Symfony\Component\Filesystem\Path;

use function constant;
use function defined;
use function dirname;
use function explode;
use function file_exists;
use function get_include_path;
use function get_included_files;
use function implode;
use function in_array;
use function is_string;
use function preg_last_error_msg;
use function preg_match;
use function preg_replace;
use function preg_split;
use function realpath;
use function str_repeat;
use function str_replace;
use function substr;

use const DIRECTORY_SEPARATOR;
use const PATH_SEPARATOR;
use const PHP_EOL;

/**
 * @internal
 */
final class IncludeAnalyzer
{
    /**
     * Cache to prevent duplicate vulnerability reports for the same location
     * @var array<string, bool>
     */
    private static array $reported_vulnerabilities = [];
    /**
     * Simple check for HTTP sources in node IDs and labels
     * @param DataFlowNode $node
     * @return string|null HTTP source type if found
     */
    private static function getHttpSourceType(DataFlowNode $node): ?string
    {
        $id = $node->id;
        $label = $node->label ?? '';
        
        if (strpos($id, '$_POST') !== false || strpos($label, '$_POST') !== false) {
            return 'POST';
        }
        if (strpos($id, '$_GET') !== false || strpos($label, '$_GET') !== false) {
            return 'GET';
        }
        if (strpos($id, '$_REQUEST') !== false || strpos($label, '$_REQUEST') !== false) {
            return 'REQUEST';
        }
        if (strpos($id, '$_COOKIE') !== false || strpos($label, '$_COOKIE') !== false) {
            return 'COOKIE';
        }
        
        return null;
    }

    /**
     * Recursively search for HTTP sources in the taint flow graph
     * @param TaintFlowGraph $graph
     * @param DataFlowNode $node
     * @param int $depth
     * @param array<string> $visited
     * @return array<string> HTTP sources found
     */
    private static function findHttpSourcesRecursive(TaintFlowGraph $graph, DataFlowNode $node, int $depth = 0, array $visited = []): array
    {
        // Prevent infinite recursion and limit depth
        if ($depth > 10 || isset($visited[$node->id])) {
            return [];
        }
        
        $visited[$node->id] = true;
        $http_sources = [];
        
        // Check if this node is an HTTP source
        $http_type = self::getHttpSourceType($node);
        if ($http_type) {
            $http_sources[] = $http_type . ': ' . $node->id;
        }
        
        // Use reflection to access private properties
        try {
            $reflection = new \ReflectionClass($graph);
            
            // Check taint sources
            $sourcesProperty = $reflection->getProperty('sources');
            $sourcesProperty->setAccessible(true);
            $sources = $sourcesProperty->getValue($graph);
            
            if (isset($sources[$node->id])) {
                $source = $sources[$node->id];
                $source_http_type = self::getHttpSourceType($source);
                if ($source_http_type) {
                    $http_sources[] = $source_http_type . ': ' . $source->id;
                }
            }
            
            // Get nodes and forward edges to traverse backwards
            $nodesProperty = $reflection->getProperty('nodes');
            $nodesProperty->setAccessible(true);
            $nodes = $nodesProperty->getValue($graph);
            
            $forwardEdgesProperty = $reflection->getProperty('forward_edges');
            $forwardEdgesProperty->setAccessible(true);
            $forward_edges = $forwardEdgesProperty->getValue($graph);
            
            // Find nodes that point to this node (traverse backwards)
            foreach ($forward_edges as $from_id => $edges) {
                if (isset($edges[$node->id]) && isset($nodes[$from_id])) {
                    $parent_node = $nodes[$from_id];
                    $parent_sources = self::findHttpSourcesRecursive($graph, $parent_node, $depth + 1, $visited);
                    $http_sources = array_merge($http_sources, $parent_sources);
                }
            }
            
        } catch (\ReflectionException $e) {
            // If reflection fails, just check the current node
        }
        
        return array_unique($http_sources);
    }

    public static function analyze(
        StatementsAnalyzer $statements_analyzer,
        PhpParser\Node\Expr\Include_ $stmt,
        Context $context,
        ?Context $global_context = null
    ): bool {
        $codebase = $statements_analyzer->getCodebase();
        $config = $codebase->config;

        if (!$config->allow_includes) {
            throw new FileIncludeException(
                'File includes are not allowed per your Psalm config - check the allowFileIncludes flag.',
            );
        }

        $was_inside_call = $context->inside_call;

        $context->inside_call = true;

        if (ExpressionAnalyzer::analyze($statements_analyzer, $stmt->expr, $context) === false) {
            $context->inside_call = $was_inside_call;

            return false;
        }

        $context->inside_call = $was_inside_call;

        $stmt_expr_type = $statements_analyzer->node_data->getType($stmt->expr);

        if ($stmt->expr instanceof PhpParser\Node\Scalar\String_
            || ($stmt_expr_type && $stmt_expr_type->isSingleStringLiteral())
        ) {
            if ($stmt->expr instanceof PhpParser\Node\Scalar\String_) {
                $path_to_file = $stmt->expr->value;
            } else {
                $path_to_file = $stmt_expr_type->getSingleStringLiteral()->value;
            }

            $path_to_file = str_replace('/', DIRECTORY_SEPARATOR, $path_to_file);

            // attempts to resolve using get_include_path dirs
            $include_path = self::resolveIncludePath($path_to_file, dirname($statements_analyzer->getFilePath()));
            $path_to_file = $include_path ?: $path_to_file;

            if (Path::isRelative($path_to_file)) {
                $path_to_file = $config->base_dir . DIRECTORY_SEPARATOR . $path_to_file;
            }
        } else {
            $path_to_file = self::getPathTo(
                $stmt->expr,
                $statements_analyzer->node_data,
                $statements_analyzer,
                $statements_analyzer->getFileName(),
                $config,
            );
        }

        // Check for extract() + include() vulnerability pattern
        // Any variable used in include() after extract() is potentially dangerous
        if ($stmt->expr instanceof PhpParser\Node\Expr\Variable 
            && is_string($stmt->expr->name)
            && isset($context->vars_in_scope['__psalm_extract_vulnerability_detected'])
        ) {
            $arg_location = new CodeLocation($statements_analyzer->getSource(), $stmt->expr);
            
            // Get the source info if available
            $source_info = 'user-controlled data';
            if (isset($context->vars_in_scope['__psalm_extract_source_info'])) {
                $source_type = $context->vars_in_scope['__psalm_extract_source_info'];
                if ($source_type->isSingleStringLiteral()) {
                    $source_info = $source_type->getSingleStringLiteral()->value;
                }
            }
            
            // Create a unique key for this vulnerability location to prevent duplicates
            $extract_message = 'WordPress LFI Vulnerability: include() uses variable $' . $stmt->expr->name . ' that can be overwritten by extract() with ' . $source_info . '. The extract() function allows attackers to overwrite any variable, including $' . $stmt->expr->name . ', leading to Local File Inclusion';
            $extract_vulnerability_key = $arg_location->file_name . ':' . $arg_location->getLineNumber() . ':' . $arg_location->getColumn() . ':' . md5($extract_message);
            
            // Only report if we haven't already reported this exact vulnerability
            if (!isset(self::$reported_vulnerabilities[$extract_vulnerability_key])) {
                self::$reported_vulnerabilities[$extract_vulnerability_key] = true;
                
                IssueBuffer::maybeAdd(
                    new TaintedWordPressLFI(
                        $extract_message,
                        $arg_location,
                        [],
                        'extract(' . $source_info . ') -> $' . $stmt->expr->name . ' overwrite -> include($' . $stmt->expr->name . ')'
                    ),
                    $statements_analyzer->getSuppressedIssues()
                );
            }
        }

        if ($stmt_expr_type
            && $statements_analyzer->data_flow_graph instanceof TaintFlowGraph
            && $stmt_expr_type->parent_nodes
            && !in_array('TaintedInput', $statements_analyzer->getSuppressedIssues())
        ) {
            // Check for both confirmed HTTP sources and WordPress-specific patterns
            $confirmed_http_sources = [];
            $wordpress_template_patterns = [];
            $all_parent_info = [];
            
            foreach ($stmt_expr_type->parent_nodes as $parent_node) {
                $all_parent_info[] = $parent_node->id;
                
                // Check for direct HTTP sources in this node
                $direct_http_type = self::getHttpSourceType($parent_node);
                if ($direct_http_type) {
                    $confirmed_http_sources[] = $direct_http_type . ': ' . $parent_node->id;
                }
                
                // Recursively search for HTTP sources in the taint flow graph
                $traced_sources = self::findHttpSourcesRecursive($statements_analyzer->data_flow_graph, $parent_node);
                $confirmed_http_sources = array_merge($confirmed_http_sources, $traced_sources);
                
                // Check for WordPress-specific template patterns (but exclude generic $this->template)
                if (strpos($parent_node->id, '$template') !== false && 
                    strpos($parent_node->id, '$this->template') === false) {
                    // This looks like a WordPress $template variable (not $this->template)
                    $wordpress_template_patterns[] = $parent_node->id;
                }
            }
            
            // Remove duplicates
            $confirmed_http_sources = array_unique($confirmed_http_sources);
            $wordpress_template_patterns = array_unique($wordpress_template_patterns);
            
            $arg_location = new CodeLocation($statements_analyzer->getSource(), $stmt->expr);
            $parent_chain = implode(' -> ', array_slice($all_parent_info, 0, 3));
            
            // Report vulnerabilities (avoid duplicates by checking both conditions together)
            $should_report = false;
            $report_message = '';
            $report_shortcode = '';
            
            if (!empty($confirmed_http_sources)) {
                $source_info = implode(', ', $confirmed_http_sources);
                $should_report = true;
                
                if (!empty($wordpress_template_patterns)) {
                    $report_message = 'WordPress LFI Vulnerability: HTTP input (' . $source_info . ') flows to include() via $template - Chain: ' . $parent_chain;
                } else {
                    $report_message = 'LFI Vulnerability: HTTP input (' . $source_info . ') flows to include() - Chain: ' . $parent_chain;
                }
                $report_shortcode = $source_info . ' -> include()';
                
            } elseif (!empty($wordpress_template_patterns)) {
                // WordPress template pattern without confirmed HTTP sources - still report as it's a known vulnerability pattern
                $template_info = implode(', ', $wordpress_template_patterns);
                $should_report = true;
                $report_message = 'WordPress LFI Pattern: Include with $template variable (check for $_POST[\'template\'] input) - Chain: ' . $parent_chain;
                $report_shortcode = $template_info . ' -> include()';
            }
            
            // Only create one report and one taint sink per include statement
            if ($should_report) {
                // Create a unique key for this vulnerability location to prevent duplicates
                $vulnerability_key = $arg_location->file_name . ':' . $arg_location->getLineNumber() . ':' . $arg_location->getColumn() . ':' . md5($report_message);
                
                // Only report if we haven't already reported this exact vulnerability
                if (!isset(self::$reported_vulnerabilities[$vulnerability_key])) {
                    self::$reported_vulnerabilities[$vulnerability_key] = true;
                    
                    IssueBuffer::maybeAdd(
                        new TaintedInclude(
                            $report_message,
                            $arg_location,
                            [],
                            $report_shortcode
                        ),
                        $statements_analyzer->getSuppressedIssues()
                    );
                }
                
                // Create taint sink (only once)
                $include_param_sink = TaintSink::getForMethodArgument(
                    'include',
                    'include',
                    0,
                    $arg_location,
                    $arg_location,
                );

                $include_param_sink->taints = [TaintKind::INPUT_INCLUDE];
                $statements_analyzer->data_flow_graph->addSink($include_param_sink);

                foreach ($stmt_expr_type->parent_nodes as $parent_node) {
                    $statements_analyzer->data_flow_graph->addPath(
                        $parent_node,
                        $include_param_sink,
                        'arg',
                    );
                }
            }
        }


        if ($path_to_file) {
            $path_to_file = self::normalizeFilePath($path_to_file);

            // if the file is already included, we can't check much more
            if (in_array(realpath($path_to_file), get_included_files(), true)) {
                return true;
            }

            $current_file_analyzer = $statements_analyzer->getFileAnalyzer();

            if ($current_file_analyzer->project_analyzer->fileExists($path_to_file)
                && !$current_file_analyzer->project_analyzer->isDirectory($path_to_file)) {
                if ($statements_analyzer->hasParentFilePath($path_to_file)
                    || !$codebase->file_storage_provider->has($path_to_file)
                    || ($statements_analyzer->hasAlreadyRequiredFilePath($path_to_file)
                        && !$codebase->file_storage_provider->get($path_to_file)->has_extra_statements)
                ) {
                    return true;
                }
                if ($config->mustBeIgnored($path_to_file)) {
                    return true;
                }

                $current_file_analyzer->addRequiredFilePath($path_to_file);

                $file_name = $config->shortenFileName($path_to_file);

                $nesting = $statements_analyzer->getRequireNesting() + 1;
                $current_file_analyzer->project_analyzer->progress->debug(
                    str_repeat('  ', $nesting) . 'checking ' . $file_name . PHP_EOL,
                );

                $include_file_analyzer = new FileAnalyzer(
                    $current_file_analyzer->project_analyzer,
                    $path_to_file,
                    $file_name,
                );

                $include_file_analyzer->setRootFilePath(
                    $current_file_analyzer->getRootFilePath(),
                    $current_file_analyzer->getRootFileName(),
                );

                $include_file_analyzer->addParentFilePath($current_file_analyzer->getFilePath());
                $include_file_analyzer->addRequiredFilePath($current_file_analyzer->getFilePath());

                foreach ($current_file_analyzer->getRequiredFilePaths() as $required_file_path) {
                    $include_file_analyzer->addRequiredFilePath($required_file_path);
                }

                foreach ($current_file_analyzer->getParentFilePaths() as $parent_file_path) {
                    $include_file_analyzer->addParentFilePath($parent_file_path);
                }

                try {
                    $include_file_analyzer->analyze(
                        $context,
                        $global_context,
                    );
                } catch (UnpreparedAnalysisException $e) {
                    if ($config->skip_checks_on_unresolvable_includes) {
                        $context->check_classes = false;
                        $context->check_variables = false;
                        $context->check_functions = false;
                    }
                }

                $included_return_type = $include_file_analyzer->getReturnType();

                if ($included_return_type) {
                    $statements_analyzer->node_data->setType($stmt, $included_return_type);
                }

                $context->has_returned = false;

                foreach ($include_file_analyzer->getRequiredFilePaths() as $required_file_path) {
                    $current_file_analyzer->addRequiredFilePath($required_file_path);
                }

                $include_file_analyzer->clearSourceBeforeDestruction();

                return true;
            }

            if (isset($context->phantom_files[$path_to_file])) {
                return true;
            }

            $var_id = ExpressionIdentifier::getExtendedVarId($stmt->expr, null);
            if ($var_id && isset($context->phantom_files[$var_id])) {
                return true;
            }

            $source = $statements_analyzer->getSource();

            IssueBuffer::maybeAdd(
                new MissingFile(
                    'Cannot find file ' . $path_to_file . ' to include',
                    new CodeLocation($source, $stmt),
                ),
                $source->getSuppressedIssues(),
            );
        } else {
            $var_id = ExpressionIdentifier::getExtendedVarId($stmt->expr, null);

            if (!$var_id || !isset($context->phantom_files[$var_id])) {
                $source = $statements_analyzer->getSource();

                IssueBuffer::maybeAdd(
                    new UnresolvableInclude(
                        'Cannot resolve the given expression to a file path',
                        new CodeLocation($source, $stmt),
                    ),
                    $source->getSuppressedIssues(),
                );
            }
        }

        if ($config->skip_checks_on_unresolvable_includes) {
            $context->check_classes = false;
            $context->check_variables = false;
            $context->check_functions = false;
        }

        return true;
    }

    /**
     * @psalm-suppress MixedAssignment
     */
    public static function getPathTo(
        PhpParser\Node\Expr $stmt,
        ?NodeDataProvider $type_provider,
        ?StatementsAnalyzer $statements_analyzer,
        string $file_name,
        Config $config
    ): ?string {
        if (Path::isRelative($file_name)) {
            $file_name = $config->base_dir . DIRECTORY_SEPARATOR . $file_name;
        }

        if ($stmt instanceof PhpParser\Node\Scalar\String_) {
            if (DIRECTORY_SEPARATOR !== '/') {
                return str_replace('/', DIRECTORY_SEPARATOR, $stmt->value);
            }
            return $stmt->value;
        }

        $stmt_type = $type_provider ? $type_provider->getType($stmt) : null;

        if ($stmt_type && $stmt_type->isSingleStringLiteral()) {
            if (DIRECTORY_SEPARATOR !== '/') {
                return str_replace(
                    '/',
                    DIRECTORY_SEPARATOR,
                    $stmt_type->getSingleStringLiteral()->value,
                );
            }

            return $stmt_type->getSingleStringLiteral()->value;
        }

        if ($stmt instanceof PhpParser\Node\Expr\ArrayDimFetch) {
            if ($stmt->var instanceof PhpParser\Node\Expr\Variable
                && $stmt->var->name === 'GLOBALS'
                && $stmt->dim instanceof PhpParser\Node\Scalar\String_
            ) {
                if (isset($GLOBALS[$stmt->dim->value]) && is_string($GLOBALS[$stmt->dim->value])) {
                    /** @var string */
                    return $GLOBALS[$stmt->dim->value];
                }
            }
        } elseif ($stmt instanceof PhpParser\Node\Expr\BinaryOp\Concat) {
            $left_string = self::getPathTo($stmt->left, $type_provider, $statements_analyzer, $file_name, $config);
            $right_string = self::getPathTo($stmt->right, $type_provider, $statements_analyzer, $file_name, $config);

            if ($left_string && $right_string) {
                return $left_string . $right_string;
            }
        } elseif ($stmt instanceof PhpParser\Node\Expr\FuncCall &&
            $stmt->name instanceof PhpParser\Node\Name &&
            $stmt->name->getParts() === ['dirname']
        ) {
            if ($stmt->getArgs()) {
                $dir_level = 1;

                if (isset($stmt->getArgs()[1])) {
                    if ($stmt->getArgs()[1]->value instanceof PhpParser\Node\Scalar\LNumber) {
                        $dir_level = $stmt->getArgs()[1]->value->value;
                    } else {
                        if ($statements_analyzer) {
                            $t = $statements_analyzer->node_data->getType($stmt->getArgs()[1]->value);
                            if ($t && $t->isSingleIntLiteral()) {
                                $dir_level = $t->getSingleIntLiteral()->value;
                            } else {
                                return null;
                            }
                        } else {
                            return null;
                        }
                    }
                }

                $evaled_path = self::getPathTo(
                    $stmt->getArgs()[0]->value,
                    $type_provider,
                    $statements_analyzer,
                    $file_name,
                    $config,
                );

                if (!$evaled_path) {
                    return null;
                }

                if ($dir_level < 1) {
                    return null;
                }

                return dirname($evaled_path, $dir_level);
            }
        } elseif ($stmt instanceof PhpParser\Node\Expr\ConstFetch) {
            $const_name = implode('', $stmt->name->getParts());

            if (defined($const_name)) {
                $constant_value = constant($const_name);

                if (is_string($constant_value)) {
                    return $constant_value;
                }
            }
        } elseif ($stmt instanceof PhpParser\Node\Scalar\MagicConst\Dir) {
            return dirname($file_name);
        } elseif ($stmt instanceof PhpParser\Node\Scalar\MagicConst\File) {
            return $file_name;
        }

        return null;
    }

    public static function resolveIncludePath(string $file_name, string $current_directory): ?string
    {
        if (!$current_directory) {
            return $file_name;
        }

        if ((substr($file_name, 0, 2) === '.' . DIRECTORY_SEPARATOR)
            || (substr($file_name, 0, 3) === '..' . DIRECTORY_SEPARATOR)
        ) {
            $file = $current_directory . DIRECTORY_SEPARATOR . $file_name;

            if (file_exists($file)) {
                return $file;
            }

            return null;
        }

        $paths = PATH_SEPARATOR === ':'
            ? preg_split('#(?<!phar):#', get_include_path())
            : explode(PATH_SEPARATOR, get_include_path());

        if ($paths === false) {
            throw new AssertionError(preg_last_error_msg());
        }
        foreach ($paths as $prefix) {
            $ds = substr($prefix, -1) === DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR;

            if ($prefix === '.') {
                $prefix = $current_directory;
            }

            $file = $prefix . $ds . $file_name;

            if (file_exists($file)) {
                return $file;
            }
        }

        return null;
    }

    /**
     * @psalm-pure
     */
    public static function normalizeFilePath(string $path_to_file): string
    {
        // replace all \ with / for normalization
        $path_to_file = str_replace('\\', '/', $path_to_file);
        $path_to_file = str_replace('/./', '/', $path_to_file);

        // first remove unnecessary / duplicates
        $path_to_file = preg_replace('/\/[\/]+/', '/', $path_to_file);

        $reduce_pattern = '/\/[^\/]+\/\.\.\//';

        while (preg_match($reduce_pattern, $path_to_file)) {
            $path_to_file = preg_replace($reduce_pattern, '/', $path_to_file, 1);
        }

        if (DIRECTORY_SEPARATOR !== '/') {
            $path_to_file = str_replace('/', DIRECTORY_SEPARATOR, $path_to_file);
        }

        return $path_to_file;
    }


}
