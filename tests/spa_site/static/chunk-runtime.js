// 只在浏览器运行时加载的业务 chunk：内含硬编码凭证，供渲染 + 本地正则链路验证。
window.__RUNTIME__ = {
  awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
  apiEndpoint: "/api/v1/user/profile",
  version: "1.4.2"
};
