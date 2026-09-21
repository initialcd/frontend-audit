// 运行时才把 chunk 地址拼出来：静态正则（CHUNK_RE / webpack 指纹）看不到它，
// 只有真的在浏览器里执行这段代码，才会发起 chunk-runtime.js 的请求并被 CDP 拦截。
// 这是"增强渲染到底有没有生效"的判定样本。
(function () {
  var seg = ['/static/', 'chunk-', 'runtime', '.js'];
  var s = document.createElement('script');
  s.src = seg.join('');
  document.head.appendChild(s);

  var req = new XMLHttpRequest();
  req.open('GET', '/api/v1/boot?ts=' + Date.now(), true);
  req.send();
})();
