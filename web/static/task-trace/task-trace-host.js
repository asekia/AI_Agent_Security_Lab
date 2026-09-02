/* task-trace-host.js — 任务轨迹的浏览器宿主（挂载层）。
 *
 * 流程：
 *   1. 依赖 task-trace-modules.js（__ModuleLoader__ + shims + 适配器 buildSnapshot）；
 *   2. fetch 原样 trajectory bundle（/static/task-trace/trajectory.js）并间接 eval；
 *   3. 用假 ctx 调 apply() 捕获 conversation.view 注册的 TrajectoryView 组件；
 *   4. 把 window.__TASK_TRACE_RUN__ 经 buildSnapshot 转成快照，挂载渲染。
 *
 * 页面需提供：
 *   - #task-trace-mount 容器（置于 .task-trace-scope[data-ds-dark-theme] 内）
 *   - window.__TASK_TRACE_RUN__（当前任务从输入到结束的完整结构化事件历史）
 */
(function () {
  "use strict";

  var M = window.__TASK_TRACE_MODULES__;
  var ReactDOM = window.ReactDOM;
  if (!M || !ReactDOM) {
    document.getElementById("task-trace-mount").innerHTML =
      '<p class="task-trace-error">宿主依赖未加载：请先引入 vendor/react(.dom).production.min.js 与 task-trace-modules.js</p>';
    return;
  }
  var requireModule = M.requireModule;
  var buildSnapshot = M.buildSnapshot;
  var t = M.t;
  var React = M.React;

  function showError(err) {
    var el = document.getElementById("task-trace-mount");
    if (el) {
      var text = err && err.message ? String(err.message) : String(err);
      el.innerHTML = '<p class="task-trace-error">轨迹视图加载失败：\n' + text.replace(/&/g, "&amp;").replace(/</g, "&lt;") + "</p>";
    }
  }

  fetch("/static/task-trace/trajectory.js?v=timeline-interaction-2", { cache: "no-store" })
    .then(function (resp) {
      if (!resp.ok) throw new Error("加载 trajectory bundle 失败 (HTTP " + resp.status + ")");
      return resp.text();
    })
    .then(function (code) {
      // 间接 eval：在全局作用域执行 bundle，注册到 __ModuleLoader__
      (0, eval)(code);
      var trajectory = requireModule("@deepseek-ai/dsh-client-ui-trajectory");
      if (!trajectory || typeof trajectory.apply !== "function") {
        throw new Error("trajectory bundle 导出异常 (apply 缺失)");
      }

      // 假 ctx：捕获 conversation.view 注册的 TrajectoryView 组件
      var captured = { view: null };
      var fakeCtx = {
        effect: function (fn) { fn(); return function () {}; },
        locale: {
          register: function () {},
          bind: function () { return t; },
        },
        slots: {
          inject: function (name, fn) { captured.inject = fn; return function () {}; },
          register: function (descriptor, Component) {
            if (descriptor && descriptor.id === "trajectory") captured.view = Component;
            return function () {};
          },
        },
        conversationEvents: { register: function () {} },
        conversationViews: { register: function () {} },
        sessions: { binding: function () { return undefined; } },
      };
      trajectory.apply(fakeCtx);
      if (typeof captured.inject === "function") captured.inject(); // 触发 register 拿到组件
      if (!captured.view) throw new Error("未捕获 TrajectoryView 组件");

      var run = window.__TASK_TRACE_RUN__;
      var hasEvents = run && Array.isArray(run.trace) && run.trace.length > 0;
      if (!hasEvents) {
        document.getElementById("task-trace-mount").innerHTML =
          '<p class="task-trace-loading">本次运行没有可展示的轨迹事件。</p>';
        return;
      }

      var SESSION = buildSnapshot(run);
      var durationState = { value: false, listeners: new Set() };

      function useSession(selector) { return selector(SESSION); }

      function useDuration(selector) {
        var pair = React.useState(function () { return selector(durationState.value); });
        React.useEffect(function () {
          var listener = function () { pair[1](selector(durationState.value)); };
          durationState.listeners.add(listener);
          return function () { durationState.listeners.delete(listener); };
        }, []);
        return pair[0];
      }
      function setActualDuration(value) {
        durationState.value = value;
        durationState.listeners.forEach(function (l) { l(); });
      }

      ReactDOM.createRoot(document.getElementById("task-trace-mount")).render(
        React.createElement(captured.view, {
          useSession: useSession,
          useDuration: useDuration,
          loadOlder: function () { return Promise.resolve(false); },
          setActualDuration: setActualDuration,
          inspect: null,
          onInspectDone: function () {},
          t: t,
        })
      );
    })
    .catch(showError);
})();
