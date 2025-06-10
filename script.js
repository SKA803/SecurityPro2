window.addEventListener('DOMContentLoaded', function() {
  // تبديل التبويبات
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
      });
      document.querySelectorAll('.tab-btn').forEach(tabBtn => {
        tabBtn.classList.remove('active');
      });
      document.getElementById(tabId)?.classList.add('active');
      btn.classList.add('active');
    });
  });

  // تبديل الوضع الليلي
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      document.body.classList.toggle('dark-mode');
      localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
      updateThemeIcon();
    });

    if (localStorage.getItem('darkMode') === 'true') {
      document.body.classList.add('dark-mode');
    }
    updateThemeIcon();
  }

  function updateThemeIcon() {
    const icon = themeToggle?.querySelector('svg');
    if (!icon) return;
    
    if (document.body.classList.contains('dark-mode')) {
      icon.innerHTML = '<path d="M12,18V6A6,6 0 0,1 18,12A6,6 0 0,1 12,18Z"/>';
    } else {
      icon.innerHTML = '<path d="M12,18C11.11,18 10.26,17.8 9.5,17.45C11.56,16.5 13,14.42 13,12C13,9.58 11.56,7.5 9.5,6.55C10.26,6.2 11.11,6 12,6A6,6 0 0,1 18,12A6,6 0 0,1 12,18Z"/>';
    }
  }

  // تحليل الكود
  const analyzeButton = document.getElementById('analyze-code');
  if (analyzeButton) {
    analyzeButton.addEventListener('click', analyzeCode);
  }

  function analyzeCode() {
    const codeType = document.getElementById('code-type')?.value;
    const codeInput = document.getElementById('code-input');
    const codeFile = document.getElementById('code-file');

    if (codeFile?.files?.length > 0) {
      const reader = new FileReader();
      reader.onload = function(e) {
        runCodeAnalysis(e.target.result, codeType);
      };
      reader.readAsText(codeFile.files[0]);
    } else if (codeInput?.value) {
      runCodeAnalysis(codeInput.value, codeType);
    } else {
      alert('الرجاء إدخال الكود أو رفع ملف لتحليله');
    }
  }

  function runCodeAnalysis(code, codeType) {
    document.getElementById('code-result').style.display = 'none';
    
    setTimeout(() => {
      let vulnerabilities = [];
      let scanner = null;

      switch (codeType) {
        case 'html': scanner = htmlScanner; break;
        case 'js': scanner = jsScanner; break;
        case 'php': scanner = phpScanner; break;
        case 'python': scanner = pythonScanner; break;
        case 'sql': scanner = sqlScanner; break;
        case 'node': scanner = nodeScanner; break;
        case 'auto':
          if (code.includes('<?php')) scanner = phpScanner;
          else if (code.includes('function(') || code.includes('=>')) scanner = jsScanner;
          else if (code.includes('<html') || code.includes('<div')) scanner = htmlScanner;
          else if (code.includes('SELECT ') || code.includes('INSERT ')) scanner = sqlScanner;
          else if (code.includes('import ') || code.includes('def ')) scanner = pythonScanner;
          else scanner = nodeScanner;
          break;
      }

      if (scanner?.scan) {
        vulnerabilities = scanner.scan(code);
      }

      const score = Math.max(0, 100 - (vulnerabilities.length * 5));
      displayResults('code', score, vulnerabilities);
      document.getElementById('code-result').style.display = 'block';
    }, 800);
  }

  // فحص الموقع
  const scanButton = document.getElementById('start-scan');
  if (scanButton) {
    scanButton.addEventListener('click', startWebsiteScan);
  }

  async function startWebsiteScan() {
    const urlInput = document.getElementById('website-url');
    const url = urlInput?.value?.trim();
    
    if (!url || !url.startsWith('http')) {
      alert('الرجاء إدخال رابط صحيح يبدأ بـ http:// أو https://');
      urlInput?.focus();
      return;
    }

    const scanOptions = Array.from(
      document.querySelectorAll('input[name="scan-options"]:checked')
    ).map(el => el.value);

    try {
      showLoading(true);
      document.getElementById('scan-result').style.display = 'none';
      
      const results = await scanWebsite(url, scanOptions);
      displayScanResults(results);
      
      document.getElementById('scan-result').style.display = 'block';
    } catch (error) {
      console.error('فحص الموقع فشل:', error);
      alert('حدث خطأ أثناء فحص الموقع: ' + error.message);
    } finally {
      showLoading(false);
    }
  }

  // تحليل SEO
  const seoButton = document.getElementById('start-seo');
  if (seoButton) {
    seoButton.addEventListener('click', startSeoAnalysis);
  }

  async function startSeoAnalysis() {
    const urlInput = document.getElementById('seo-url');
    const url = urlInput?.value?.trim();
    
    if (!url || !url.startsWith('http')) {
      alert('الرجاء إدخال رابط صحيح يبدأ بـ http:// أو https://');
      urlInput?.focus();
      return;
    }

    const seoOptions = Array.from(
      document.querySelectorAll('input[name="seo-options"]:checked')
    ).map(el => el.value);

    try {
      showSeoLoading(true);
      document.getElementById('seo-result').style.display = 'none';
      
      const results = await seoScanner.scan(url, seoOptions);
      displaySeoResults(results);
      
      document.getElementById('seo-result').style.display = 'block';
    } catch (error) {
      console.error('تحليل SEO فشل:', error);
      alert('حدث خطأ أثناء تحليل SEO: ' + error.message);
    } finally {
      showSeoLoading(false);
    }
  }

  // قائمة التحقق الأمنية
  const saveChecklistButton = document.getElementById('save-checklist');
  if (saveChecklistButton) {
    saveChecklistButton.addEventListener('click', saveChecklistProgress);
  }

  function saveChecklistProgress() {
    const checklistItems = Array.from(
      document.querySelectorAll('.checklist-item input[type="checkbox"]')
    ).map(checkbox => checkbox.checked);
    
    localStorage.setItem('checklistProgress', JSON.stringify(checklistItems));
    alert('تم حفظ تقدمك في قائمة التحقق الأمنية');
  }

  function loadChecklistProgress() {
    const savedProgress = localStorage.getItem('checklistProgress');
    if (savedProgress) {
      const checklistItems = JSON.parse(savedProgress);
      document.querySelectorAll('.checklist-item input[type="checkbox"]').forEach((checkbox, index) => {
        if (checklistItems[index]) {
          checkbox.checked = true;
        }
      });
    }
  }

  // تحميل التقدم المحفوظ عند بدء التطبيق
  loadChecklistProgress();

  // وظائف المساعدة المشتركة
  function showLoading(show) {
    const loadingElement = document.getElementById('scan-loading');
    if (loadingElement) {
      loadingElement.style.display = show ? 'block' : 'none';
    }
  }

  function showSeoLoading(show) {
    const loadingElement = document.getElementById('seo-loading');
    if (loadingElement) {
      loadingElement.style.display = show ? 'block' : 'none';
    }
  }

  function displayScanResults(results) {
    if (!results) return;

    // تحديث النتائج لكل قسم
    ['security', 'performance', 'seo'].forEach(section => {
      const container = document.getElementById(`${section}-results`);
      if (container && results[section]) {
        container.innerHTML = results[section].map(item => `
          <div class="scan-item ${item.severity || ''}">
            <div class="scan-item-title">${item.title}</div>
            <div class="scan-item-desc">${item.description}</div>
            ${item.solution ? `<div class="scan-item-solution"><strong>الحل:</strong> ${item.solution}</div>` : ''}
          </div>
        `).join('');
      }
    });

    // تحديث النتيجة العامة
    updateResultScore('scan', results.overallScore || 0);
  }

  function displaySeoResults(results) {
    if (!results) return;

    // تحديث النتائج لكل قسم
    ['meta', 'keywords', 'structure'].forEach(section => {
      const container = document.getElementById(`${section}-results`);
      if (container && results[section]) {
        container.innerHTML = results[section].map(item => `
          <div class="seo-item ${item.severity || ''}">
            <div class="seo-item-title">${item.title}</div>
            <div class="seo-item-desc">${item.description}</div>
            ${item.solution ? `<div class="seo-item-solution"><strong>الحل:</strong> ${item.solution}</div>` : ''}
            ${item.example ? `<div class="seo-item-example"><strong>مثال:</strong> ${item.example}</div>` : ''}
          </div>
        `).join('');
      }
    });

    // تحديث النتيجة العامة
    updateResultScore('seo', results.overallScore || 0);
  }

  function updateResultScore(type, score) {
    const container = document.getElementById(`${type}-result`);
    if (!container) return;

    container.querySelector('.result-score').textContent = `${score}%`;
    
    const progressBar = container.querySelector('.progress-bar');
    if (progressBar) {
      progressBar.style.width = `${score}%`;
      progressBar.textContent = `${score}%`;
      progressBar.style.background = getScoreColor(score);
    }
  }

  function getScoreColor(score) {
    if (score >= 90) return 'var(--success)';
    if (score >= 70) return 'var(--warning)';
    if (score >= 50) return 'var(--orange)';
    if (score >= 30) return 'var(--danger)';
    return 'var(--dark-red)';
  }

  // دالة عرض النتائج العامة
  function displayResults(type, score, vulnerabilities) {
    const container = document.getElementById(`${type}-result`);
    if (!container) return;

    updateResultScore(type, score);

    const vulnContainer = container.querySelector('.vulnerabilities');
    if (vulnContainer) {
      vulnContainer.innerHTML = vulnerabilities.length === 0 ? `
        <div class="vulnerability info">
          <div class="vulnerability-title">
            <svg viewBox="0 0 24 24"><path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M12,4C7.58,4 4,7.58 4,12C4,16.42 7.58,20 12,20C16.42,20 20,16.42 20,12C20,7.58 16.42,4 12,4M11,16.5L6.5,12L7.91,10.59L11,13.67L16.59,8.09L18,9.5L11,16.5Z"/></svg>
            لا توجد ثغرات خطيرة
          </div>
          <div class="vulnerability-desc">تهانينا! يبدو أن ${type === 'code' ? 'الكود' : 'الموقع'} آمن نسبياً.</div>
        </div>
      ` : vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity}">
          <div class="vulnerability-title">
            ${getSeverityIcon(vuln.severity)} ${vuln.title}
          </div>
          <div class="vulnerability-desc">${vuln.description}</div>
          <div class="vulnerability-solution"><strong>الحل:</strong> ${vuln.solution}</div>
        </div>
      `).join('');
    }
  }

  function getSeverityIcon(severity) {
    const icons = {
      critical: '<svg viewBox="0 0 24 24"><path d="M11.5,20L16.36,10.27H6.64L11.5,20M12,2C6.47,2 2,6.5 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/></svg>',
      high: '<svg viewBox="0 0 24 24"><path d="M12,2L1,21H23M11,10V14H13V10M11,16V18H13V16"/></svg>',
      medium: '<svg viewBox="0 0 24 24"><path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/></svg>',
      low: '<svg viewBox="0 0 24 24"><path d="M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20Z"/></svg>'
    };
    return icons[severity] || icons.low;
  }
});