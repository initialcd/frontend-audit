"""验证新增规则能覆盖今天（Drupal 靶标）的全部发现。"""
from core.prefilter import (
    analyze_url_for_cms_findings,
    detect_json_config_secrets,
    detect_source_code_exposure,
    prefilter_js,
    prefilter_text,
)


def test_cms_sensitive_paths_composer_json():
    """composer.json 依赖声明泄露。"""
    findings = analyze_url_for_cms_findings(
        "https://www.haifeng.4001961200.com/composer.json"
    )
    assert findings, "composer.json 应命中 CMS 敏感路径"
    assert findings[0].ftype == "dependency_file"
    assert findings[0].severity == "high"


def test_cms_sensitive_paths_installed_json():
    """installed.json 精确版本泄露。"""
    findings = analyze_url_for_cms_findings(
        "https://www.haifeng.4001961200.com/vendor/composer/installed.json"
    )
    assert findings, "installed.json 应命中"
    assert findings[0].ftype == "dependency_file"
    assert findings[0].severity == "critical"


def test_cms_sensitive_paths_settings_php():
    """Drupal settings.php 泄露。"""
    findings = analyze_url_for_cms_findings(
        "https://www.haifeng.4001961200.com/sites/default/settings.php"
    )
    assert findings, "settings.php 应命中"
    assert findings[0].ftype == "cms_config"
    assert findings[0].severity == "critical"


def test_cms_sensitive_paths_theme_source():
    """Drupal 主题源码/配置泄露。"""
    for url in (
        "https://www.haifeng.4001961200.com/themes/szrcb/szrcb.info.yml",
        "https://www.haifeng.4001961200.com/themes/szrcb/szrcb.theme",
        "https://www.haifeng.4001961200.com/themes/szrcb/szrcb.libraries.yml",
    ):
        findings = analyze_url_for_cms_findings(url)
        assert findings, f"{url} 应命中主题源码规则"


def test_cms_sensitive_paths_vendor_bin():
    """vendor/bin/drush 暴露。"""
    findings = analyze_url_for_cms_findings(
        "https://www.haifeng.4001961200.com/vendor/bin/drush"
    )
    assert findings, "vendor/bin 应命中"
    assert findings[0].ftype == "binary_exposure"


def test_cms_sensitive_paths_bootstrap_inc():
    """bootstrap.inc 源码泄露（nginx 配置错误）。"""
    findings = analyze_url_for_cms_findings(
        "https://www.haifeng.4001961200.com/core/includes/bootstrap.inc"
    )
    assert findings, "bootstrap.inc 应命中 source_disclosure"
    assert findings[0].ftype == "source_disclosure"


def test_source_code_exposure_php_in_inc():
    """检测 .inc 文件返回 PHP 源码。"""
    php_source = b"""<?php
/**
 * @file
 * Functions that need to be loaded on every Drupal request.
 */
use Drupal\\Component\\Utility\\Crypt;
use Drupal\\Core\\Config\\BootstrapConfigStorageFactory;

const DRUPAL_MINIMUM_PHP = '7.0.8';

function drupal_bootstrap($phase = NULL) {
  // ...
}

class DrupalKernel {
  public function boot() {
    return $this;
  }
}
"""
    findings = detect_source_code_exposure(
        php_source,
        "https://www.haifeng.4001961200.com/core/includes/bootstrap.inc",
        "text/plain",
    )
    assert findings, "PHP 源码特征应被检测为源码泄露"
    assert findings[0].ftype == "source_code_disclosure"
    assert findings[0].severity == "high"


def test_source_code_exposure_no_false_positive():
    """正常 HTML 页面不应误报。"""
    html = (
        "<!DOCTYPE html>\n"
        "<html><head><title>homepage</title></head>\n"
        "<body><h1>welcome</h1><p>text</p></body></html>\n"
    ).encode("utf-8")
    findings = detect_source_code_exposure(
        html,
        "https://www.haifeng.4001961200.com/",
        "text/html",
    )
    assert findings == [], "普通 HTML 不应误报源码泄露"


def test_json_config_hash_leak():
    """drupal-settings-json 中的 permissionsHash 泄露。"""
    config_json = (
        '<script type="application/json" data-drupal-selector="drupal-settings-json">'
        '{"user":{"uid":0,'
        '"permissionsHash":"0ee66c0bd48fe85f34312648cda380299a0961c2bfc6cb8bbfcf2866bdc6d5b5"}}'
        "</script>"
    )
    findings = detect_json_config_secrets(config_json)
    assert findings, "permissionsHash 应被检测为配置哈希泄露"
    assert findings[0].ftype == "config_hash_leak"
    assert "permissionsHash" in findings[0].value


def test_hash_token_secret_pattern():
    """通用密钥正则扩展：hash 类字段。"""
    js = 'var cfg = { csrfToken: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" };'
    pf = prefilter_js(js, 40, 4000)
    assert any(f.ftype == "hash_token" for f in pf.findings)


def test_version_detection_drupal():
    """Drupal 版本号通过 ?v= 参数检测。"""
    js = '<script src="/core/misc/drupal.js?v=8.9.3"></script>'
    pf = prefilter_js(js, 40, 4000)
    versions = [f.value for f in pf.findings if f.ftype == "version"]
    assert any("8.9.3" in v for v in versions), f"应检测到 8.9.3，实际: {versions}"
