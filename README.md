<h1>Psalm</h1>

[![Packagist](https://img.shields.io/packagist/v/vimeo/psalm.svg)](https://packagist.org/packages/vimeo/psalm)
[![Packagist](https://img.shields.io/packagist/dt/vimeo/psalm.svg)](https://packagist.org/packages/vimeo/psalm)
[![Psalm coverage](https://shepherd.dev/github/vimeo/psalm/coverage.svg?)](https://shepherd.dev/github/vimeo/psalm)
[![Psalm level](https://shepherd.dev/github/vimeo/psalm/level.svg?)](https://psalm.dev/)

Psalm is a static analysis tool for finding errors in PHP applications. This fork mainly used for personal research.

## Usage

- Run `git clone https://github.com/H0j3n/psalm.git`
- Run `composer install` in Psalm directory
- Run `./psalm init` in Psalm directory
- Run `./psalm --taint-analysis <FOLDER>` in Psalm directory

## Updates History

- Fix few functions to enable run without "Could not find any composer autoloaders" errors.
    - https://github.com/vimeo/psalm/issues/4025#issuecomment-678843787
    - Commit: https://github.com/H0j3n/psalm/commit/eda089c98b4614b9104bb53520e53f498bb394b3

## Who made this

Built by Matt Brown ([@muglug](https://github.com/muglug)).

Maintained by Orklah ([@orklah](https://github.com/orklah)), Daniil Gentili ([@danog](https://github.com/danog)), and Bruce Weirdan ([@weirdan](https://github.com/weirdan)).

The engineering team at [Vimeo](https://github.com/vimeo) have provided a lot encouragement, especially [@nbeliard](https://github.com/nbeliard), [@erunion](https://github.com/erunion) and [@nickyr](https://github.com/nickyr).
