<?php

namespace zxf\Security\Tests;

class TestExtensionProvider
{
    public static function getItems(): array
    {
        return ['jpg', 'png'];
    }

    public static function resolve(): array
    {
        return ['gif', 'webp'];
    }

    public function toArray(): array
    {
        return ['pdf', 'doc'];
    }

    public function __invoke(): array
    {
        return ['txt', 'csv'];
    }

    public function getConfig(): array
    {
        return ['md', 'json'];
    }

    public function all(): array
    {
        return ['xml', 'yaml'];
    }
}
