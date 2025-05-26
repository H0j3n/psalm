<?php

namespace Psalm\Plugin;

use Psalm\Plugin\EventHandler\Event\AfterExpressionAnalysisEvent;
use Psalm\Plugin\EventHandler\AfterExpressionAnalysisInterface;
use Psalm\Plugin\EventHandler\Event\AfterFunctionCallAnalysisEvent;
use Psalm\Plugin\EventHandler\AfterFunctionCallAnalysisInterface;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Variable;
use Psalm\CodeLocation;
use Psalm\Issue\TaintedWordPressLFI;
use Psalm\IssueBuffer;
use Psalm\StatementsSource;

/**
 * WordPress LFI Plugin for enhanced detection of Local File Inclusion vulnerabilities
 * Specifically designed to catch patterns like CVE-2025-2294 (Kubio plugin)
 */
class WordPressLFIPlugin implements AfterFunctionCallAnalysisInterface
{
    /**
     * WordPress functions that can lead to LFI if user input is passed to them
     */
    private const WORDPRESS_LFI_FUNCTIONS = [
        'get_template_part',
        'load_template',
        'include',
        'include_once',
        'require',
        'require_once',
    ];

    /**
     * User input sources that should be considered tainted
     */
    private const USER_INPUT_SOURCES = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_SERVER',
    ];

    public static function afterFunctionCallAnalysis(AfterFunctionCallAnalysisEvent $event): ?bool
    {
        $expr = $event->getExpr();
        $statements_source = $event->getStatementsSource();
        
        if (!$expr instanceof FuncCall) {
            return null;
        }

        $function_name = self::getFunctionName($expr);
        if (!$function_name || !in_array($function_name, self::WORDPRESS_LFI_FUNCTIONS, true)) {
            return null;
        }

        // Check if any arguments contain user input
        foreach ($expr->args as $arg_index => $arg) {
            if (self::containsUserInput($arg->value)) {
                $code_location = new CodeLocation($statements_source, $expr);
                
                $message = sprintf(
                    'Potential WordPress LFI vulnerability: User input passed to %s() function. '
                    . 'This pattern is similar to CVE-2025-2294 (Kubio plugin vulnerability). '
                    . 'Ensure proper validation and sanitization of user input.',
                    $function_name
                );

                IssueBuffer::accepts(
                    new TaintedWordPressLFI(
                        $message,
                        $code_location,
                        [],
                        ''
                    ),
                    $statements_source->getSuppressedIssues()
                );
            }
        }

        return null;
    }

    /**
     * Extract function name from FuncCall node
     */
    private static function getFunctionName(FuncCall $expr): ?string
    {
        if ($expr->name instanceof Node\Name) {
            return $expr->name->toString();
        }
        
        return null;
    }

    /**
     * Check if an expression contains user input (recursive check)
     */
    private static function containsUserInput(Node\Expr $expr): bool
    {
        // Direct superglobal access
        if ($expr instanceof ArrayDimFetch) {
            $var = $expr->var;
            if ($var instanceof Variable && is_string($var->name)) {
                $var_name = '$' . $var->name;
                if (in_array($var_name, self::USER_INPUT_SOURCES, true)) {
                    return true;
                }
            }
        }

        // Array containing user input
        if ($expr instanceof Array_) {
            foreach ($expr->items as $item) {
                if ($item && self::containsUserInput($item->value)) {
                    return true;
                }
            }
        }

        // Variable that might contain user input (simplified check)
        if ($expr instanceof Variable && is_string($expr->name)) {
            $var_name = '$' . $expr->name;
            if (in_array($var_name, self::USER_INPUT_SOURCES, true)) {
                return true;
            }
        }

        // Function call that might return user input (like Arr::get($_REQUEST, ...))
        if ($expr instanceof FuncCall || $expr instanceof Node\Expr\StaticCall || $expr instanceof Node\Expr\MethodCall) {
            // Check if any arguments contain user input
            if (isset($expr->args)) {
                foreach ($expr->args as $arg) {
                    if (self::containsUserInput($arg->value)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
} 