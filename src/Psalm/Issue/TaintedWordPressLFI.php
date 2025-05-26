<?php

namespace Psalm\Issue;

final class TaintedWordPressLFI extends TaintedInput
{
    public const SHORTCODE = 256;
} 