<?php

namespace zxf\Security\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;

/**
 * 路由服务提供者 - 修复版
 *
 * 注册包内的路由，提供资源文件访问
 * 资源路由需要排除安全中间件
 */
class RouteServiceProvider extends ServiceProvider
{
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
        // 创建专门用于资源文件的路由组，排除安全中间件
        Route::middleware('web')
            ->namespace($this->namespace)
            ->group(function () {
                // CSS 文件路由
                Route::get('/zxf/security/css/{file}', function ($file) {
                    return $this->serveAsset('css', $file);
                })->where('file', '.*\.css$')->name('security.assets.css');

                // JS 文件路由
                Route::get('/zxf/security/js/{file}', function ($file) {
                    return $this->serveAsset('js', $file);
                })->where('file', '.*\.js$')->name('security.assets.js');

                // 图片文件路由
                Route::get('/zxf/security/images/{file}', function ($file) {
                    return $this->serveAsset('images', $file);
                })->where('file', '.*\.(png|jpg|jpeg|gif|svg|ico)$')->name('security.assets.images');

                // 字体文件路由
                Route::get('/zxf/security/fonts/{file}', function ($file) {
                    return $this->serveAsset('fonts', $file);
                })->where('file', '.*\.(woff|woff2|ttf|eot)$')->name('security.assets.fonts');
            });
    }

    /**
     * 提供资源文件
     */
    protected function serveAsset(string $type, string $file)
    {
        $basePath = __DIR__ . "/../../Resources/{$type}";
        $path = "{$basePath}/{$file}";

        // 安全检查：防止目录遍历攻击
        $realBasePath = realpath($basePath);
        $realPath = realpath($path);

        if (!$realPath || !str_starts_with($realPath, $realBasePath)) {
            abort(404, "Resource not found: {$file}");
        }

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

        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $contentType = $mimeTypes[$extension] ?? 'text/plain';

        // 设置缓存头
        $headers = [
            'Content-Type' => $contentType,
            'Cache-Control' => 'public, max-age=31536000', // 1年缓存
            'Expires' => gmdate('D, d M Y H:i:s \G\M\T', time() + 31536000),
        ];

        // 添加 ETag 用于缓存验证
        $etag = md5($path . filemtime($path));
        $headers['ETag'] = $etag;

        // 检查客户端缓存
        $clientEtag = request()->header('If-None-Match');
        if ($clientEtag && $clientEtag === $etag) {
            return response('', 304, $headers);
        }

        return response()
            ->file($path, $headers);
    }
}
