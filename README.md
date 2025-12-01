# Laravel Security Middleware - Laravel 安全拦截中间件


![](https://img.shields.io/packagist/dt/zxf/security) ![](https://img.shields.io/github/stars/zhaoxianfang/util.svg) ![](https://img.shields.io/github/forks/zhaoxianfang/util.svg) ![](https://img.shields.io/github/tag/zhaoxianfang/util.svg) ![](https://img.shields.io/github/release/zhaoxianfang/util.svg) ![](https://img.shields.io/github/issues/zhaoxianfang/util.svg)

高级安全拦截中间件包，为Laravel应用提供全面的安全防护。

## 🚀 主要优化特性

### 配置管理优化
- **智能配置解析**：自动识别动态配置和静态配置
- **防止误解析**：明确指定不应解析为可调用方法的配置项
- **内存缓存**：仅当前请求有效的性能优化

### 路由资源优化
- **无需发布资源**：通过路由直接访问包内CSS、JS文件
- **CDN友好**：支持缓存控制和版本管理
- **类型安全**：严格的文件类型检查

### 性能优化
- **取消非必要缓存**：仅保留速率限制缓存
- **内存优化**：减少不必要的对象创建
- **分层检测**：从轻量级到重量级的递进检查

### 安全检测增强
- **多层防护**：9个安全检测层面
- **自定义处理器**：支持各个检测层面的自定义逻辑
- **误报过滤**：智能识别和过滤误报

### 用户体验优化
- **美观界面**：现代化的拦截页面设计
- **响应式设计**：完美支持各种设备
- **深色模式**：自动适应系统主题
- **无障碍支持**：完整的ARIA标签和键盘导航

## 📦 安装

```bash
composer require zxf/security
```
 ## 🚀 使用方法

### 发布
```bash

# 一键安装（推荐）
php artisan security:install
# 等同于
php artisan vendor:publish --provider="zxf\Security\Providers\SecurityServiceProvider"

# 强制安装（覆盖现有文件）
php artisan security:install --force

# 安装但不运行迁移
php artisan security:install --no-migrate

# 仅发布配置文件
php artisan vendor:publish --tag=security-config

# 仅发布数据迁移
php artisan vendor:publish --tag=security-migrations
```