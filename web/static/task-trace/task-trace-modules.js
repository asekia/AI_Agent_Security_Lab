/* task-trace-modules.js — 任务轨迹运行时的公共部分（浏览器 / Node 测试共用）。
 *
 * 职责：
 *   1. 最小模块加载器（__ModuleLoader__），供 trajectory bundle 原样运行；
 *   2. 五个依赖 shim（react / react-dom / jsx-runtime / dsh-client-runtime /
 *      dsh-client-ui-primitives），只实现 bundle 用到的导出；
 *   3. 数据适配器：把运行 trace 事件（thought / tool_call / tool_result /
 *      denied / node / final）转换为任务轨迹的 eventNodes + requests 快照模型；
 *   4. 中文文案 t()。
 *
 * 浏览器顺序：react UMD → react-dom UMD → 本文件 → task-trace-host.js
 */
(function (global) {
  "use strict";

  var React = global.React;
  if (!React) throw new Error("[task-trace] 未找到 React（请先加载 vendor/react.production.min.js）");

  /* ================= 1. 模块加载器 ================= */
  var registry = {};
  function requireModule(id) {
    var entry = registry[id];
    if (!entry) throw new Error("[task-trace] 模块未注册: " + id);
    if (entry.exports !== undefined) return entry.exports;
    entry.exports = entry.factory(function (dep) { return requireModule(dep); });
    return entry.exports;
  }
  global.__ModuleLoader__ = {
    load: function (def) { registry[def.id] = { factory: def.factory, exports: undefined }; },
  };

  /* ================= 2. 依赖 shim ================= */
  function defineModule(id, factory) { registry[id] = { factory: factory, exports: undefined }; }

  // 2.1 react / react-dom / jsx-runtime
  defineModule("react", function () { return React; });
  defineModule("react-dom", function () { return global.ReactDOM; });
  defineModule("react/jsx-runtime", function () {
    // 新 JSX transform 约定：jsx(type, config, maybeKey) — 第三参是 key，绝不能当 children
    function jsx(type, config, maybeKey) {
      if (maybeKey !== undefined && config !== null) {
        config = Object.assign({}, config);
        config.key = maybeKey;
      }
      return React.createElement(type, config);
    }
    return { jsx: jsx, jsxs: jsx, Fragment: React.Fragment, jsxDEV: jsx };
  });

  // 2.2 @deepseek-ai/dsh-client-runtime/client（仅事件管线用到，独立渲染不会被调用）
  defineModule("@deepseek-ai/dsh-client-runtime/client", function () {
    return {
      contextForm: function (v) { return v; },
      contextProvenance: function (v) { return v; },
      createSnapshotStore: function (initial) {
        var state = initial;
        var listeners = new Set();
        return {
          getState: function () { return state; },
          setState: function (patch) {
            state = typeof patch === "function" ? patch(state) : Object.assign({}, state, patch);
            listeners.forEach(function (l) { l(state); });
            return state;
          },
          subscribe: function (l) { listeners.add(l); return function () { listeners.delete(l); }; },
          getInitialState: function () { return initial; },
        };
      },
      displayFailureMessage: function (err) {
        return err && err.message ? String(err.message) : String(err);
      },
      emptyAssistantBlock: function (blockType) { return { kind: blockType, text: "" }; },
      isTokenDelta: function () { return false; },
      toAssistantBlock: function (block) { return block; },
      toAssistantBlocks: function (blocks) { return Array.isArray(blocks) ? blocks : []; },
    };
  });

  // 2.3 @deepseek-ai/dsh-client-ui-primitives（图标 / JsonTree / MarkdownText / Tooltip）
  defineModule("@deepseek-ai/dsh-client-ui-primitives", function () {
    function svg(props, children) {
      var p = Object.assign({
        width: 16, height: 16, viewBox: "0 0 24 24", fill: "none",
        "aria-hidden": "true",
      }, props, {
        stroke: props.stroke || "currentColor",
        strokeWidth: props.strokeWidth || 1.8,
        strokeLinecap: props.strokeLinecap || "round",
        strokeLinejoin: props.strokeLinejoin || "round",
      });
      return React.createElement("svg", p, children);
    }
    function IconSearchOutline16(props) {
      return svg(props, [
        React.createElement("circle", { key: "c", cx: 11, cy: 11, r: 6 }),
        React.createElement("path", { key: "h", d: "M15.5 15.5 20 20" }),
      ]);
    }
    function IconUserOutline16(props) {
      return svg(props, [
        React.createElement("circle", { key: "h", cx: 12, cy: 7.5, r: 3.2 }),
        React.createElement("path", { key: "s", d: "M5 20.5c1.2-3.6 3.6-5.5 7-5.5s5.8 1.9 7 5.5" }),
      ]);
    }
    function IconSparkle16(props) {
      return svg(props, [React.createElement("path", {
        key: "s", d: "M12 3c.6 4.6 2.4 6.4 7 7-4.6.6-6.4 2.4-7 7-.6-4.6-2.4-6.4-7-7 4.6-.6 6.4-2.4 7-7z",
      })]);
    }
    function IconSettingsOutline16(props) {
      return svg(props, [
        React.createElement("circle", { key: "g", cx: 12, cy: 12, r: 3 }),
        React.createElement("path", {
          key: "s",
          d: "M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M18.7 5.3l-1.6 1.6M6.9 17.1l-1.6 1.6",
        }),
      ]);
    }
    function IconChevronRightOutline14(props) {
      return svg(props, [React.createElement("path", { key: "c", d: "M9 6l6 6-6 6" })]);
    }

    function JsonTree(props) {
      var data = props.data;
      var label = props.label;
      var className = props.className;
      return React.createElement(
        "div",
        { className: className || undefined },
        typeof label === "string" && label !== ""
          ? React.createElement("div", { className: "dsh-json-label" }, label)
          : null,
        React.createElement(
          "pre",
          { className: "dsh-json-pre" },
          JSON.stringify(data, null, 2)
        )
      );
    }

    function esc(s) {
      return String(s)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
    function renderMarkdown(src) {
      var blocks = [];
      src = String(src);
      src = src.replace(/```[^\n]*\n?([\s\S]*?)```/g, function (m, code) {
        blocks.push(code.replace(/\n$/, ""));
        return "\u0000CODE" + (blocks.length - 1) + "\u0000";
      });
      src = esc(src);
      src = src.replace(/`([^`\n]+)`/g, "<code>$1</code>");
      src = src.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      src = src.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");
      src = src
        .split(/\n{2,}/)
        .map(function (p) { return p.trim() === "" ? "" : "<p>" + p.replace(/\n/g, "<br>") + "</p>"; })
        .join("");
      src = src.replace(/\u0000CODE(\d+)\u0000/g, function (m, i) {
        return "<pre><code>" + esc(blocks[Number(i)]) + "</code></pre>";
      });
      return src;
    }
    function MarkdownText(props) {
      return React.createElement("div", {
        className: "dsh-markdown",
        dangerouslySetInnerHTML: { __html: renderMarkdown(props.text) },
      });
    }

    function Tooltip(props) {
      var raw = props.label !== undefined ? props.label : (props.content !== undefined ? props.content : props.title);
      var text = typeof raw === "function" ? raw() : raw;
      return React.createElement(
        "span",
        {
          className: "dsh-tooltip-wrap",
          "data-side": props.side || "right",
          style: props.delayMs != null ? { "--dsh-tooltip-delay": props.delayMs + "ms" } : undefined,
        },
        props.children,
        text !== undefined && text !== null && text !== ""
          ? React.createElement("span", { className: "dsh-tooltip-bubble", role: "tooltip" }, text)
          : null
      );
    }

    function extractMarkdownPlainText(source) {
      return String(source == null ? "" : source)
        .replace(/```[\s\S]*?```/g, function (m) { return m.replace(/```/g, "").trim(); })
        .replace(/`([^`]*)`/g, "$1")
        .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
        .replace(/^#{1,6}\s+/gm, "")
        .replace(/\*\*([^*]+)\*\*/g, "$1")
        .replace(/\*([^*]+)\*/g, "$1");
    }

    return {
      JsonTree: JsonTree,
      MarkdownText: MarkdownText,
      Tooltip: Tooltip,
      extractMarkdownPlainText: extractMarkdownPlainText,
      IconSearchOutline16: IconSearchOutline16,
      IconUserOutline16: IconUserOutline16,
      IconSparkle16: IconSparkle16,
      IconSettingsOutline16: IconSettingsOutline16,
      IconChevronRightOutline14: IconChevronRightOutline14,
    };
  });

  /* ================= 3. 中文文案 ================= */
  var ZH = {
    "view.trajectory": "轨迹",
    "toolbar.aria": "轨迹工具栏",
    "toolbar.duration": "Duration",
    "toolbar.useActualDuration": "Use actual duration",
    "toolbar.useEqualWidth": "Use equal-width operations",
    "toolbar.actualTime": "实际时间",
    "toolbar.turns": "Turns",
    "toolbar.expandTurns": "Expand turns",
    "toolbar.collapseTurns": "Collapse turns",
    "toolbar.calls": "Calls",
    "toolbar.expandCalls": "Expand calls",
    "toolbar.collapseCalls": "Collapse calls",
    "toolbar.search": "搜索轨迹",
    "toolbar.searchPlaceholder": "搜索",
  };
  function t(key) { return ZH[key] !== undefined ? ZH[key] : key; }

  /* ================= 4. 数据适配器：运行 trace → 任务轨迹快照 ================= */
  function buildSnapshot(run) {
    var events = run && Array.isArray(run.trace) ? run.trace : [];
    var prompt = (run && (run.prompt || run.scenario)) || "";
    var nodes = [];
    var requests = [];
    var seq = 0;
    var PER_EVENT_MS = 1200;
    var base = events.length > 0 ? Date.now() - events.length * PER_EVENT_MS : Date.now();
    var startOf = function (i) { return base + i * PER_EVENT_MS; };
    var endOf = function (i) { return startOf(i) + 900; };

    // 一次任务内的完整工具调用索引。按 call_id 精确匹配；旧格式无 call_id 时按工具名 FIFO 匹配。
    var callsById = new Map();
    var pendingCallIdsByName = new Map();
    var stepTimes = {};  // step -> { startedAt, completedAt }

    function rememberCall(call) {
      callsById.set(call.callId, call);
      var queue = pendingCallIdsByName.get(call.name);
      if (!queue) {
        queue = [];
        pendingCallIdsByName.set(call.name, queue);
      }
      queue.push(call.callId);
    }

    function takeCall(ev, name) {
      var explicitId = ev.call_id || ev.callId || ev.tool_call_id;
      if (explicitId != null && String(explicitId) !== "") {
        var byId = callsById.get(String(explicitId));
        if (byId) return byId;
      }
      var queue = pendingCallIdsByName.get(name) || [];
      while (queue.length > 0) {
        var queued = callsById.get(queue.shift());
        if (queued && !queued.settled) return queued;
      }
      return null;
    }

    function recordStep(step, start, end) {
      if (!stepTimes[step]) stepTimes[step] = { startedAt: start, completedAt: end };
      else stepTimes[step].completedAt = end;
    }

    if (prompt) {
      nodes.push({
        kind: "user",
        seq: ++seq,
        turn: 1,
        step: 0,
        time: startOf(0) - 400,
        content: [{ type: "text", text: prompt }],
        source: { kind: "user" },
      });
    }

    events.forEach(function (ev, i) {
      var type = ev.type;
      var step = Number(ev.step) || i + 1;
      var start = startOf(i);
      var end = endOf(i);

      if (type === "thought") {
        var content = ev.content != null ? String(ev.content) : "";
        if (content.trim() === "") return;
        nodes.push({
          kind: "assistant",
          seq: ++seq,
          turn: 1,
          step: step,
          time: end,
          timing: { stepStartTime: start },
          blocks: [{ kind: "reasoning", text: content }],
        });
        recordStep(step, start, end);
        return;
      }

      if (type === "final") {
        var text = ev.content != null ? String(ev.content) : "";
        if (text.trim() === "") return;
        nodes.push({
          kind: "assistant",
          seq: ++seq,
          turn: 1,
          step: step,
          time: end,
          timing: { stepStartTime: start },
          blocks: [{ kind: "text", text: text }],
        });
        recordStep(step, start, end);
        return;
      }

      if (type === "tool_call") {
        var args = ev.args != null ? ev.args : {};
        var explicitCallId = ev.call_id || ev.callId || ev.tool_call_id;
        var callId = explicitCallId != null && String(explicitCallId) !== ""
          ? String(explicitCallId)
          : "call_" + (seq + 1) + "_" + step;
        var argsRaw = (function () {
          try { return JSON.stringify(args, null, 2); } catch (e) { return String(args); }
        })();
        var call = {
          name: String(ev.name || "tool"),
          callId: callId,
          argsRaw: argsRaw,
          time: start,
          turn: 1,
          step: step,
          settled: false,
        };
        rememberCall(call);
        nodes.push({
          kind: "assistant",
          seq: ++seq,
          turn: 1,
          step: step,
          time: start,
          timing: { stepStartTime: start },
          blocks: [{
            kind: "tool-call",
            name: call.name,
            callId: callId,
            argsRaw: argsRaw,
          }],
        });
        recordStep(step, start, end);
        return;
      }

      if (type === "tool_result" || type === "denied") {
        var name = String(ev.name || "tool");
        var resultText = ev.result != null ? String(ev.result) : "";
        var isDenied = type === "denied" || resultText.indexOf("[denied]") === 0;
        var matchedCall = takeCall(ev, name);
        if (matchedCall) {
          matchedCall.settled = true;
          // 视图会把该 tool-result 节点并入相同 callId 的工具行；节点必须保留，不能直接丢弃。
          nodes.push({
            kind: "tool-result",
            seq: ++seq,
            time: end,
            callId: matchedCall.callId,
            call: { name: matchedCall.name, argsRaw: matchedCall.argsRaw },
            callTime: matchedCall.time,
            content: [{ type: "text", text: resultText }],
            isError: isDenied || resultText.indexOf("[error]") === 0,
            error: isDenied ? { name: "Denied", code: "approval_denied" } : undefined,
          });
          recordStep(matchedCall.step, matchedCall.time, end);
          return;
        }
        // 没有对应 tool_call 的孤立结果仍按时间顺序保留，避免丢失任务历史。
        nodes.push({
          kind: "tool-result",
          seq: ++seq,
          time: end,
          callId: "orphan_" + seq + "_" + step,
          call: { name: name, argsRaw: "{}" },
          callTime: start,
          content: [{ type: "text", text: resultText }],
          isError: isDenied || resultText.indexOf("[error]") === 0,
          error: isDenied ? { name: "Denied", code: "approval_denied" } : undefined,
        });
        recordStep(step, start, end);
        return;
      }

      // node 类型（多 agent 路由节点）→ 消息单元格
      var nodeText = [ev.name, ev.result].filter(function (v) { return v != null && v !== ""; }).join(": ");
      if (nodeText.trim() !== "") {
        nodes.push({
          kind: "assistant",
          seq: ++seq,
          turn: 1,
          step: step,
          time: end,
          timing: { stepStartTime: start },
          blocks: [{ kind: "text", text: nodeText }],
        });
        recordStep(step, start, end);
      }
    });

    // 请求记录：为每个 assistant step 生成一条（驱动 Step 编号 / 状态 / 耗时展示）
    Object.keys(stepTimes).forEach(function (step) {
      var tm = stepTimes[step];
      requests.push({
        purpose: "assistant",
        turn: 1,
        step: Number(step),
        startSeq: tm.startedAt, // 仅当某 step 缺节点时才参与布局排序；此处用时间兜底
        resultSeq: tm.completedAt,
        startedAt: tm.startedAt,
        completedAt: tm.completedAt,
        status: "complete",
        provenance: { provider: "lab", model: "mock" },
        requestConfig: { provider: "lab", model: "mock", purpose: "assistant" },
      });
    });

    return {
      openState: "complete",
      loadingOlder: false,
      hasMore: false,
      views: new Map([["trajectory", {
        eventNodes: nodes,
        eventLocations: new Map(),
        partial: null,
        runningCalls: [],
        requests: requests,
        callSchemas: undefined,
      }]]),
    };
  }

  global.__TASK_TRACE_MODULES__ = {
    requireModule: requireModule,
    buildSnapshot: buildSnapshot,
    t: t,
    React: React,
  };
})(typeof window !== "undefined" ? window : globalThis);
