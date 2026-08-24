from core.renderer import is_spa_shell


def test_typical_spa_shell():
    html = '<!DOCTYPE html><html><body><div id="app"></div><script src="/js/app.js"></script></body></html>'
    assert is_spa_shell(html, ["/js/app.js"]) is True


def test_nextjs_shell():
    html = '<html><body><div id="__next"></div><script src="/_next/static/chunk.js"></script></body></html>'
    assert is_spa_shell(html, ["/_next/static/chunk.js"]) is True


def test_content_page_not_shell():
    html = ('<html><body><h1>欢迎</h1><p>' + '这是真实页面内容' * 100
            + '</p><script src="/js/app.js"></script></body></html>')
    assert is_spa_shell(html, ["/js/app.js"]) is False


def test_no_scripts_not_shell():
    html = '<html><body><div id="app"></div></body></html>'
    assert is_spa_shell(html, []) is False
