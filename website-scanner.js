const websiteScanner = {
  scan: async function(url, scanType = 'quick') {
    try {
      // التحقق من صحة الرابط
      if (!this.isValidUrl(url)) {
        throw new Error('رابط الموقع غير صالح');
      }

      // إضافة البروتوكول إذا لم يكن موجوداً
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }

      // نتائج الفحص الأساسية
      const scanResults = {
        url: url,
        scanType: scanType,
        score: 100, // تبدأ من 100 وتنقص مع كل مشكلة
        vulnerabilities: [],
        details: {}
      };

      // تنفيذ الفحوصات حسب النوع
      if (scanType === 'quick' || scanType === 'full') {
        await this.checkHTTPS(url, scanResults);
        await this.checkSecurityHeaders(url, scanResults);
        await this.checkServerInfo(url, scanResults);
      }

      if (scanType === 'full' || scanType === 'headers') {
        await this.checkCORS(url, scanResults);
        await this.checkXSSProtection(url, scanResults);
      }

      if (scanType === 'full' || scanType === 'performance') {
        await this.checkPerformance(url, scanResults);
      }

      // حساب النتيجة النهائية
      this.calculateFinalScore(scanResults);

      return scanResults;
    } catch (error) {
      console.error('حدث خطأ أثناء فحص الموقع:', error);
      throw error;
    }
  },

  isValidUrl: function(url) {
    try {
      new URL(url);
      return true;
    } catch (e) {
      return false;
    }
  },

  checkHTTPS: async function(url, results) {
    try {
      const response = await fetch(url, { 
        method: 'HEAD',
        redirect: 'manual',
        cache: 'no-store'
      });

      if (url.startsWith('http://')) {
        results.vulnerabilities.push({
          title: 'الاتصال غير آمن (HTTP)',
          severity: 'high',
          description: 'الموقع لا يستخدم HTTPS مما يعرض البيانات للتنصت.',
          solution: 'قم بشراء وتثبيت شهادة SSL/TLS وقم بتكوين إعادة توجيه من HTTP إلى HTTPS.'
        });
        results.score -= 15;
      }

      // التحقق من إعادة التوجيه الصحيحة
      if (response.status === 301 || response.status === 302) {
        const location = response.headers.get('location');
        if (location && location.startsWith('http://')) {
          results.vulnerabilities.push({
            title: 'إعادة توجيه غير آمنة',
            severity: 'medium',
            description: 'يتم إعادة التوجيه إلى نسخة HTTP غير آمنة من الموقع.',
            solution: 'تأكد من أن جميع إعادة التوجيه تؤدي إلى HTTPS وليس HTTP.'
          });
          results.score -= 10;
        }
      }
    } catch (error) {
      console.error('خطأ في فحص HTTPS:', error);
    }
  },

  checkSecurityHeaders: async function(url, results) {
    const requiredHeaders = [
      'Content-Security-Policy',
      'X-Content-Type-Options',
      'X-Frame-Options',
      'X-XSS-Protection',
      'Strict-Transport-Security'
    ];

    try {
      const response = await fetch(url, { 
        method: 'HEAD',
        redirect: 'manual',
        cache: 'no-store'
      });

      const missingHeaders = [];
      const headers = {};

      requiredHeaders.forEach(header => {
        const value = response.headers.get(header);
        headers[header] = value || 'غير موجود';
        
        if (!value) {
          missingHeaders.push(header);
        }
      });

      results.details.headers = headers;

      if (missingHeaders.length > 0) {
        results.vulnerabilities.push({
          title: 'رؤوس أمان مفقودة',
          severity: 'medium',
          description: `الرؤوس الأمنية التالية مفقودة: ${missingHeaders.join(', ')}`,
          solution: 'أضف رؤوس الأمان التالية إلى إعدادات الخادم: ' + missingHeaders.join(', ')
        });
        results.score -= missingHeaders.length * 2;
      }
    } catch (error) {
      console.error('خطأ في فحص رؤوس الأمان:', error);
    }
  },

  checkServerInfo: async function(url, results) {
    try {
      const response = await fetch(url, { 
        method: 'HEAD',
        redirect: 'manual',
        cache: 'no-store'
      });

      const serverHeader = response.headers.get('server');
      const xPoweredBy = response.headers.get('x-powered-by');

      results.details.serverInfo = {
        server: serverHeader || 'غير معروف',
        poweredBy: xPoweredBy || 'غير معروف'
      };

      if (serverHeader || xPoweredBy) {
        results.vulnerabilities.push({
          title: 'معلومات الخادم مرئية',
          severity: 'low',
          description: `يتم عرض معلومات الخادم: ${serverHeader || ''} ${xPoweredBy || ''}`,
          solution: 'قم بتعطيل عرض إصدار الخادم في إعدادات الخادم.'
        });
        results.score -= 5;
      }
    } catch (error) {
      console.error('خطأ في فحص معلومات الخادم:', error);
    }
  },

  checkCORS: async function(url, results) {
    try {
      // محاولة طلب CORS لفحص الإعدادات
      const response = await fetch(url, {
        method: 'OPTIONS',
        headers: {
          'Origin': 'https://example.com',
          'Access-Control-Request-Method': 'GET'
        }
      });

      const corsHeaders = {
        'Access-Control-Allow-Origin': response.headers.get('access-control-allow-origin'),
        'Access-Control-Allow-Methods': response.headers.get('access-control-allow-methods'),
        'Access-Control-Allow-Credentials': response.headers.get('access-control-allow-credentials')
      };

      results.details.cors = corsHeaders;

      if (corsHeaders['Access-Control-Allow-Origin'] === '*') {
        results.vulnerabilities.push({
          title: 'سياسة CORS متساهلة',
          severity: 'medium',
          description: 'رأس Access-Control-Allow-Origin مضبوط على * مما يسمح لأي موقع بالوصول إلى الموارد.',
          solution: 'قم بتقييد النطاقات المسموح بها في رأس Access-Control-Allow-Origin.'
        });
        results.score -= 10;
      }

      if (corsHeaders['Access-Control-Allow-Credentials'] === 'true' && 
          corsHeaders['Access-Control-Allow-Origin'] === '*') {
        results.vulnerabilities.push({
          title: 'إعدادات CORS غير آمنة',
          severity: 'high',
          description: 'السماح ببيانات الاعتماد (credentials) مع سياسة CORS مفتوحة (*) يعرض البيانات للخطر.',
          solution: 'لا تسمح ببيانات الاعتماد مع سياسة CORS مفتوحة أو قم بتقييد النطاقات المسموح بها.'
        });
        results.score -= 15;
      }
    } catch (error) {
      console.error('خطأ في فحص CORS:', error);
    }
  },

  checkXSSProtection: async function(url, results) {
    try {
      const response = await fetch(url, { 
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store'
      });

      const xssHeader = response.headers.get('x-xss-protection');
      results.details.xssProtection = xssHeader || 'غير مفعل';

      if (!xssHeader || xssHeader === '0') {
        results.vulnerabilities.push({
          title: 'حماية XSS غير مفعلة',
          severity: 'medium',
          description: 'رأس X-XSS-Protection غير مفعل أو معطل.',
          solution: 'قم بتمكين حماية XSS عن طريق إضافة رأس X-XSS-Protection: 1; mode=block'
        });
        results.score -= 8;
      }
    } catch (error) {
      console.error('خطأ في فحص حماية XSS:', error);
    }
  },

  checkPerformance: async function(url, results) {
    try {
      // هذا مثال مبسط، في الواقع يمكن استخدام Lighthouse API أو أدوات أخرى
      const startTime = performance.now();
      const response = await fetch(url, { 
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store'
      });
      const endTime = performance.now();
      const loadTime = endTime - startTime;

      results.details.performance = {
        loadTime: loadTime.toFixed(2) + 'ms',
        size: response.headers.get('content-length') || 'غير معروف'
      };

      if (loadTime > 3000) { // أكثر من 3 ثواني
        results.vulnerabilities.push({
          title: 'أداء التحميل ضعيف',
          severity: 'low',
          description: `وقت تحميل الصفحة ${loadTime.toFixed(2)}ms وهو أعلى من المعدل الموصى به.`,
          solution: 'قم بتحسين أداء الموقع عن طريق ضغط الصور، تمكين التخزين المؤقت، واستخدام CDN.'
        });
        results.score -= 5;
      }

      // التحقق من ضغط Gzip
      const contentEncoding = response.headers.get('content-encoding');
      if (!contentEncoding || !contentEncoding.includes('gzip')) {
        results.vulnerabilities.push({
          title: 'ضغط المحتوى غير مفعل',
          severity: 'low',
          description: 'الموقع لا يستخدم ضغط Gzip للمحتوى مما يزيد من حجم التحميل.',
          solution: 'قم بتمكين ضغط Gzip في إعدادات الخادم.'
        });
        results.score -= 5;
      }
    } catch (error) {
      console.error('خطأ في فحص الأداء:', error);
    }
  },

  calculateFinalScore: function(results) {
    // التأكد من أن النتيجة بين 0 و 100
    results.score = Math.max(0, Math.min(100, results.score));
    
    // تصنيف مستوى الأمان
    if (results.score >= 90) {
      results.securityLevel = 'ممتاز';
    } else if (results.score >= 70) {
      results.securityLevel = 'جيد';
    } else if (results.score >= 50) {
      results.securityLevel = 'متوسط';
    } else {
      results.securityLevel = 'ضعيف';
    }
  }
};

// دالة مساعدة للاستخدام في الملف الرئيسي
async function scanWebsite(url, scanType = 'quick') {
  try {
    // إظهار حالة التحميل
    document.getElementById('scan-loading').style.display = 'flex';
    document.getElementById('scan-result').style.display = 'none';
    
    // تنفيذ الفحص
    const results = await websiteScanner.scan(url, scanType);
    
    // إخفاء التحميل وإظهار النتائج
    document.getElementById('scan-loading').style.display = 'none';
    document.getElementById('scan-result').style.display = 'block';
    
    // عرض النتائج
    displayScanResults(results);
    
    return results;
  } catch (error) {
    document.getElementById('scan-loading').style.display = 'none';
    alert('حدث خطأ أثناء فحص الموقع: ' + error.message);
    throw error;
  }
}

function displayScanResults(results) {
  const container = document.getElementById('scan-result');
  const scoreElement = container.querySelector('.result-score');
  const progressBar = container.querySelector('.progress-bar');
  const vulnContainer = container.querySelector('.vulnerabilities');
  
  // تحديث النتيجة
  scoreElement.textContent = `${results.score}% (${results.securityLevel})`;
  
  // تحديث شريط التقدم
  progressBar.style.width = `${results.score}%`;
  progressBar.textContent = `${results.score}%`;
  
  // تحديد لون الشريط حسب النتيجة
  if (results.score >= 90) {
    progressBar.style.background = 'linear-gradient(to right, var(--success), #5cb85c)';
  } else if (results.score >= 70) {
    progressBar.style.background = 'linear-gradient(to right, var(--warning), var(--success))';
  } else if (results.score >= 50) {
    progressBar.style.background = 'linear-gradient(to right, var(--warning), #f0ad4e)';
  } else if (results.score >= 30) {
    progressBar.style.background = 'linear-gradient(to right, var(--danger), var(--warning))';
  } else {
    progressBar.style.background = 'linear-gradient(to right, var(--danger), #d9534f)';
  }
  
  // عرض الثغرات
  vulnContainer.innerHTML = '';
  
  if (results.vulnerabilities.length === 0) {
    const noVuln = document.createElement('div');
    noVuln.className = 'vulnerability info';
    noVuln.innerHTML = `
      <div class="vulnerability-title">
        <svg viewBox="0 0 24 24">
          <path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M12,4C7.58,4 4,7.58 4,12C4,16.42 7.58,20 12,20C16.42,20 20,16.42 20,12C20,7.58 16.42,4 12,4M11,16.5L6.5,12L7.91,10.59L11,13.67L16.59,8.09L18,9.5L11,16.5Z"/>
        </svg>
        لا توجد ثغرات خطيرة
      </div>
      <div class="vulnerability-desc">تهانينا! يبدو أن موقعك آمن نسبياً. استمر في الحفاظ على ممارسات التطوير الآمن.</div>
    `;
    vulnContainer.appendChild(noVuln);
  } else {
    results.vulnerabilities.forEach(vuln => {
      const vulnElement = document.createElement('div');
      vulnElement.className = `vulnerability ${vuln.severity}`;
      
      let icon = '';
      if (vuln.severity === 'critical') {
        icon = '<svg viewBox="0 0 24 24"><path d="M11.5,20L16.36,10.27H6.64L11.5,20M12,2C6.47,2 2,6.5 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,7H13V13H11V7Z"/></svg>';
      } else if (vuln.severity === 'high') {
        icon = '<svg viewBox="0 0 24 24"><path d="M12,2L1,21H23M12,6L19.53,19H4.47M11,10V14H13V10M11,16V18H13V16"/></svg>';
      } else if (vuln.severity === 'medium') {
        icon = '<svg viewBox="0 0 24 24"><path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/></svg>';
      } else {
        icon = '<svg viewBox="0 0 24 24"><path d="M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z"/></svg>';
      }
      
      vulnElement.innerHTML = `
        <div class="vulnerability-title">${icon} ${vuln.title}</div>
        <div class="vulnerability-desc">${vuln.description}</div>
        <div class="vulnerability-solution"><strong>الحل:</strong> ${vuln.solution}</div>
      `;
      
      vulnContainer.appendChild(vulnElement);
    });
  }
  
  // عرض التفاصيل الإضافية
  const detailsContainer = document.createElement('div');
  detailsContainer.className = 'scan-details';
  detailsContainer.innerHTML = `
    <h4>تفاصيل الفحص:</h4>
    <pre>${JSON.stringify(results.details, null, 2)}</pre>
  `;
  vulnContainer.appendChild(detailsContainer);
}