<?php

namespace Zxf\Security\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;

/**
 * 路由服务提供者
 *
 * 注册包内的路由，提供资源文件访问
 */
class RouteServiceProvider extends ServiceProvider
{
    /**
     * 命名空间
     */
    protected $namespace = 'Zxf\\Security\\Http\\Controllers';

    /**
     * 启动服务
     */
    public function boot(): void
    {
        parent::boot();
    }

    /**
     * 注册路由
     */
    public function map(): void
    {
        $this->mapAssetRoutes();
    }

    /**
     * 注册资源文件路由
     */
    protected function mapAssetRoutes(): void
    {
        Route::middleware('web')
            ->namespace($this->namespace)
            ->group(function () {
                // CSS 文件路由
                Route::get('/vendor/security/css/{file}', function ($file) {
                    return $this->serveAsset('css', $file);
                })->where('file', '.*\.css$');

                // JS 文件路由
                Route::get('/vendor/security/js/{file}', function ($file) {
                    return $this->serveAsset('js', $file);
                })->where('file', '.*\.js$');

                // 图片文件路由
                Route::get('/vendor/security/images/{file}', function ($file) {
                    return $this->serveAsset('images', $file);
                })->where('file', '.*\.(png|jpg|jpeg|gif|svg|ico)$');

                // 字体文件路由
                Route::get('/vendor/security/fonts/{file}', function ($file) {
                    return $this->serveAsset('fonts', $file);
                })->where('file', '.*\.(woff|woff2|ttf|eot)$');
            });
    }

    /**
     * 提供资源文件
     */
    protected function serveAsset(string $type, string $file)
    {
        $path = __DIR__ . "/../../Resources/{$type}/{$file}";

        if (!file_exists($path) || !is_file($path)) {
            abort(404, "Resource not found: {$file}");
        }

        $mimeTypes = [
            'css' => 'text/css',
            'js' => 'application/javascript',
            'png' => 'image/png',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
            'ico' => 'image/x-icon',
            'woff' => 'font/woff',
            'woff2' => 'font/woff2',
            'ttf' => 'font/ttf',
            'eot' => 'application/vnd.ms-fontobject',
        ];

        $extension = pathinfo($file, PATHINFO_EXTENSION);
        $contentType = $mimeTypes[$extension] ?? 'text/plain';

        return response()
            ->file($path, [
                'Content-Type' => $contentType,
                'Cache-Control' => 'public, max-age=31536000', // 1年缓存
            ]);
    }
}