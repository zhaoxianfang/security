// 创建背景粒子动画
function createParticles() {
    const bgAnimation = document.getElementById('bgAnimation');
    const particleCount = 30;

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');

        // 随机大小和位置
        const size = Math.random() * 10 + 5;
        const posX = Math.random() * 100;
        const delay = Math.random() * 15;

        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;
        particle.style.left = `${posX}%`;
        particle.style.animationDelay = `${delay}s`;

        bgAnimation.appendChild(particle);
    }
}

// 格式化时间戳
function formatTimestamp() {
    const timestamp = "2025-11-13T01:13:39.108728Z";
    const date = new Date(timestamp);
    const formatted = date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZone: 'Asia/Shanghai'
    });

    document.getElementById('formattedTimestamp').textContent = formatted;
}

// 盾牌交互效果
function setupShieldInteraction() {
    const shield = document.querySelector('.shield');

    // 添加鼠标悬停效果
    shield.addEventListener('mouseover', function() {
        this.style.animation = 'shield-pulse 0.8s infinite alternate';
    });

    shield.addEventListener('mouseout', function() {
        this.style.animation = 'shield-pulse 2.5s infinite alternate';
    });

    // 添加点击效果
    shield.addEventListener('click', function() {
        this.style.transform = 'scale(1.15) rotate(5deg)';
        setTimeout(() => {
            this.style.transform = '';
        }, 500);
    });
}

// JSON 语法高亮
function syntaxHighlight(json) {
    if (typeof json != 'string') {
        json = JSON.stringify(json, undefined, 2);
    }
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'json-number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'json-key';
            } else {
                cls = 'json-string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'json-boolean';
        } else if (/null/.test(match)) {
            cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

// 初始化 JSON 上下文数据
function initJsonContext() {
    const jsonElement = document.getElementById('jsonContext');
    jsonElement.innerHTML = syntaxHighlight(jsonElement.innerHTML);
}
function initJsonErrors() {
    const jsonElement = document.getElementById('jsonErrors');
    jsonElement.innerHTML = syntaxHighlight(jsonElement.innerHTML);
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    createParticles();
    formatTimestamp();
    setupShieldInteraction();
    initJsonContext();
    initJsonErrors();
});