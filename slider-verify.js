(() => {
  const version = 'DBvSA9Gg';

  const cloudflare = async () => {
    try {
      const res = await fetch("https://speed.cloudflare.com/meta");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      return {
        ip: json.clientIp ?? "",
        location: `${json.country ?? ""} ${json.region ?? ""} ${json.city ?? ""} - ${json.asOrganization ?? ""}`.trim(),
        info: json,
      };
    } catch {
      return { ip: null, location: null, info: null };
    }
  };

  class Verification {
    constructor() {
      this.elements = {};
      this.init();
    }

    init() {
      this.setupTheme();  // 初始化主题
      this.injectStyles();
      this.createContainer();
      this.createInitialView();
      this.bindEvents();
      this.loadIPInfo();
    }

    setupTheme() {
      // 从 localStorage 读取 theme，默认 light
      const theme = localStorage.getItem("theme") || "light";
      document.documentElement.classList.toggle("dark", theme === "dark");
    }

    injectStyles() {
      const style = document.createElement('style');
      style.id = 'verification-styles';
      style.textContent = `
        :root { 
          --brand-color:#6366f1;
          --brand-hover:#4f46e5;
          --success-color:#10b981;
          --error-color:#ef4444;
          --light-gray:#f1f5f9;
          --medium-gray:#94a3b8;
          --dark-gray:#475569;
          --text-color:#0f172a;
          --text-secondary:#64748b;
          --bg-color:rgba(255,255,255,.95);
          --overlay-bg:rgba(15,23,42,.6);
          --shadow-sm:0 1px 2px 0 rgb(0 0 0 / 0.05);
          --shadow-md:0 4px 6px -1px rgb(0 0 0 / 0.1),0 2px 4px -2px rgb(0 0 0 / 0.1);
          --shadow-lg:0 10px 15px -3px rgb(0 0 0 / 0.1),0 4px 6px -4px rgb(0 0 0 / 0.1);
          --shadow-xl:0 20px 25px -5px rgb(0 0 0 / 0.1),0 8px 10px -6px rgb(0 0 0 / 0.1);
        }

        /* ===== 暗黑模式覆盖 ===== */
        .dark {
          --text-color:#f1f5f9;
          --text-secondary:#94a3b8;
          --bg-color:rgba(30,41,59,.95);
          --overlay-bg:rgba(0,0,0,.7);
          --light-gray:#334155;
          --medium-gray:#64748b;
          --dark-gray:#94a3b8;
        }

        *{box-sizing:border-box;}
        #verify-container{position:fixed;inset:0;display:flex;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;z-index:9999;background:var(--overlay-bg);backdrop-filter:blur(8px);opacity:0;animation:fadeIn 0.4s ease-out forwards;}
        .verify-box{background:var(--bg-color);border:1px solid rgba(255,255,255,.1);padding:28px 24px;border-radius:16px;text-align:center;width:360px;max-width:90vw;box-shadow:var(--shadow-xl);backdrop-filter:blur(20px);transform:translateY(20px) scale(0.95);animation:modalIn 0.5s 0.1s ease-out forwards;}
        .verify-box.fade-out{animation:modalOut 0.4s ease-out forwards;}
        .verify-header{margin-bottom:24px;}
        .verify-title{font-size:22px;font-weight:700;color:var(--text-color);margin:0 0 12px 0;letter-spacing:-0.025em;}
        .verify-message{color:var(--text-secondary);font-size:15px;line-height:1.6;font-weight:400;}
        .interaction-wrapper{display:flex;align-items:center;background:linear-gradient(135deg,#f8fafc 0%,#f1f5f9 100%);border:1px solid rgba(148,163,184,.2);border-radius:12px;padding:16px 14px;cursor:pointer;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden;}
        .dark .interaction-wrapper{background:linear-gradient(135deg,#1e293b 0%,#334155 100%);border-color:rgba(148,163,184,.3);}
        .interaction-wrapper::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(99,102,241,.1),transparent);transition:left 0.5s ease;}
        .interaction-wrapper:hover{background:linear-gradient(135deg,#f1f5f9 0%,#e2e8f0 100%);border-color:rgba(99,102,241,.3);transform:translateY(-2px);box-shadow:var(--shadow-md);}
        .dark .interaction-wrapper:hover{background:linear-gradient(135deg,#334155 0%,#475569 100%);}
        .interaction-wrapper:hover::before{left:100%;}
        .interaction-wrapper:active{transform:translateY(0);box-shadow:var(--shadow-sm);}
        .checkbox{width:32px;height:32px;border:2px solid var(--medium-gray);border-radius:8px;display:flex;justify-content:center;align-items:center;flex-shrink:0;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);background:white;box-shadow:var(--shadow-sm);}
        .dark .checkbox{background:#1e293b;border-color:var(--dark-gray);}
        .interaction-wrapper:hover .checkbox{border-color:var(--brand-color);transform:scale(1.05);}
        .label{color:var(--text-color);font-weight:600;font-size:16px;margin-left:16px;transition:color 0.3s ease;}
        .interaction-wrapper:hover .label{color:var(--brand-color);}
        .icon{width:100%;height:100%;}
        .spinner{animation:spin 1s cubic-bezier(0.68,-0.55,0.265,1.55) infinite;}
        .success-checkmark path{stroke-dasharray:48;stroke-dashoffset:48;animation:draw 0.6s cubic-bezier(0.65,0,0.45,1) forwards;}
        .progress-bar{height:6px;background:rgba(241,245,249,.8);border-radius:3px;overflow:hidden;margin-top:20px;position:relative;transition:opacity 0.3s ease;}
        .dark .progress-bar{background:rgba(51,65,85,.8);}
        .progress-bar.complete{animation:barComplete 0.6s ease-out forwards;}
        .progress-bar::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);animation:shimmer 2s infinite;}
        .progress-fill{height:100%;width:0;background:linear-gradient(90deg,var(--brand-color),var(--brand-hover));border-radius:3px;position:relative;overflow:hidden;transition:width .3s ease;}
        .progress-fill::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);animation:shimmer 1.5s infinite;}
        .progress-label{font-size:14px;color:var(--text-secondary);margin-top:12px;opacity:0;transition:opacity 0.3s ease;}
        .footer{margin-top:24px;font-size:13px;color:var(--text-secondary);font-weight:500;opacity:0.7;transition:opacity 0.3s ease;word-break:break-word;}
        .verify-box:hover .footer{opacity:1;}
        .hidden{display:none !important;}
        @keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}
        @keyframes fadeIn{to{opacity:1;}}
        @keyframes modalIn{to{opacity:1;transform:translateY(0) scale(1);}}
        @keyframes modalOut{to{opacity:0;transform:translateY(20px) scale(0.95);}}
        @keyframes draw{to{stroke-dashoffset:0;}}
        @keyframes shimmer{0%{transform:translateX(-100%);}100%{transform:translateX(100%);}}
        @keyframes barComplete{0%{transform:scaleX(1);background:linear-gradient(90deg,var(--brand-color),var(--brand-hover));}50%{transform:scaleX(1.01);background:linear-gradient(90deg,var(--success-color),#34d399);}100%{transform:scaleX(1);background:var(--success-color);}}
        @media(max-width:480px){.verify-box{padding:20px 16px;width:90%;}.verify-title{font-size:20px;}.label{font-size:15px;}}
      `;
      document.head.appendChild(style);
    }

    createContainer() {
      this.elements.container = document.createElement('div');
      this.elements.container.id = 'verify-container';
      this.elements.box = document.createElement('div');
      this.elements.box.className = 'verify-box';
      this.elements.container.appendChild(this.elements.box);
      document.body.appendChild(this.elements.container);
    }

    createInitialView() {
      this.elements.box.innerHTML = `
        <div class="verify-header">
          <h1 id="verify-title" class="verify-title">验证您的连接是安全的</h1>
          <p class="verify-message">在继续访问之前，我们需要进行一次快速的安全检查。</p>
        </div>
        <div id="interaction-trigger" class="interaction-wrapper" tabindex="0" role="button" aria-label="点击以验证">
          <div class="checkbox"></div>
          <span class="label">点击以验证</span>
        </div>
        <p class="footer" id="footer-text">Moon365 Security</p>
      `;
    }

    bindEvents() {
      const trigger = this.elements.box.querySelector('#interaction-trigger');
      trigger.addEventListener('click', () => this.startVerification());
      trigger.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' || e.key === ' ') this.startVerification();
      });
    }

    startVerification() {
      this.createVerifyingView();
      setTimeout(() => {
        this.createSuccessView();
        this.loadMainApp();
      }, 1500);
    }

    createVerifyingView() {
      const trigger = this.elements.box.querySelector('#interaction-trigger');
      trigger.style.pointerEvents = 'none';
      const checkbox = trigger.querySelector('.checkbox');
      checkbox.innerHTML = `
        <svg class="icon spinner" fill="none" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="10" stroke="var(--light-gray)" stroke-width="4"></circle>
          <path d="M12 2a10 10 0 0 1 10 10" stroke="var(--brand-color)" stroke-width="4" stroke-linecap="round"></path>
        </svg>
      `;
      trigger.querySelector('.label').textContent = '正在验证...';
    }

    createSuccessView() {
      const trigger = this.elements.box.querySelector('.interaction-wrapper');
      trigger.querySelector('.label').textContent = '验证成功';
      trigger.querySelector('.checkbox').innerHTML = `
        <svg class="icon success-checkmark" fill="none" viewBox="0 0 24 24">
          <path stroke="var(--success-color)" stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/>
        </svg>
      `;
      this.elements.box.querySelector('.verify-title').textContent = '太棒了！';
      this.elements.box.querySelector('.verify-message').textContent = '您已通过验证，即将为您加载页面。';
      
      const progressContainer = document.createElement('div');
      progressContainer.innerHTML = `
        <div class="progress-bar">
          <div id="progress-fill" class="progress-fill"></div>
        </div>
        <div id="progress-label" class="progress-label"></div>
      `;
      this.elements.box.appendChild(progressContainer);
      this.elements.progressFill = progressContainer.querySelector('#progress-fill');
      this.elements.progressLabel = progressContainer.querySelector('#progress-label');
      
      setTimeout(() => this.elements.progressLabel.style.opacity = '1', 100);
    }

    async loadMainApp() {
      const scriptUrl = window.location.origin + '/assets/index-' + version + '.js';
      const timeout = setTimeout(() => this.showError('加载超时，请刷新页面重试。'), 15000);
      try {
        const response = await fetch(scriptUrl, { mode: 'cors' });
        if (!response.ok) throw new Error(`脚本加载失败: ${response.status}`);
        const contentLength = response.headers.get('Content-Length');
        if (!contentLength || !response.body) {
          this.loadMainAppFallback(scriptUrl, timeout);
          return;
        }
        const total = parseInt(contentLength, 10);
        let loaded = 0;
        const reader = response.body.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          loaded += value.length;
          const progress = Math.min((loaded / total) * 100, 95);
          this.elements.progressFill.style.width = `${progress}%`;
          this.updateProgressLabel(progress);
        }
        const blob = new Blob(chunks, { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        this.injectScript(url, timeout, () => URL.revokeObjectURL(url));
      } catch (e) {
        console.error("加载主应用出错:", e);
        this.showError('网络连接中断或脚本路径错误，请刷新页面重试。', e);
        clearTimeout(timeout);
      }
    }

    loadMainAppFallback(scriptUrl, timeout) {
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress > 95) progress = 95;
        this.elements.progressFill.style.width = `${progress}%`;
        this.updateProgressLabel(progress);
      }, 200);
      this.injectScript(scriptUrl, timeout, () => clearInterval(interval));
    }

    updateProgressLabel(progress) {
      if (progress < 25) {
        this.elements.progressLabel.textContent = '正在下载资源文件...';
      } else if (progress < 75) {
        this.elements.progressLabel.textContent = '正在准备页面资源...';
      } else {
        this.elements.progressLabel.textContent = '加载即将完成...';
      }
    }

    injectScript(src, timeout, onFinally) {
      const script = document.createElement('script');
      script.type = 'module';
      script.src = src;
      script.onload = () => {
        clearTimeout(timeout);
        this.elements.progressFill.style.width = '100%';
        this.elements.progressFill.parentElement.classList.add('complete');
        this.elements.progressLabel.textContent = '加载完成！';
        setTimeout(() => this.cleanup(), 800);
        if (onFinally) onFinally();
      };
      script.onerror = () => {
        clearTimeout(timeout);
        this.showError('执行失败，请联系客服检查主文件是否正确。');
        if (onFinally) onFinally();
      };
      document.body.appendChild(script);
    }

    showError(msg) {
      this.elements.box.innerHTML = `
        <div class="verify-header">
          <h1 class="verify-title" style="color:var(--error-color)">验证失败</h1>
          <p class="verify-message">${msg}</p>
        </div>
        <p class="footer">Moon365 Security</p>
      `;
    }

    cleanup() {
      this.elements.box.classList.add('fade-out');
      setTimeout(() => {
        this.elements.container.remove();
        document.getElementById('verification-styles')?.remove();
      }, 400);
    }

    async loadIPInfo() {
      const ipData = await cloudflare();
      if (ipData.ip && this.elements.box) {
        const footer = this.elements.box.querySelector('#footer-text');
        footer.textContent += ` | IP: ${ipData.ip}, ${ipData.info?.country}`;
      }
    }
  }

  new Verification();
})();