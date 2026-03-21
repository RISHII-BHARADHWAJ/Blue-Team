
document.addEventListener('DOMContentLoaded', function () {

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function (e) {
            const inputs = form.querySelectorAll('input[required], textarea[required]');
            let isValid = true;

            inputs.forEach(input => {
                if (!input.value.trim()) {
                    isValid = false;
                    input.classList.add('is-invalid');
                } else {
                    input.classList.remove('is-invalid');
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Please fill in all required fields');
            }
        });
    });

    const currentPage = window.location.pathname.split('/').pop() || 'index.php';
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage) {
            link.classList.add('active');
        }
    });

    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    });

    const yearElements = document.querySelectorAll('.current-year');
    yearElements.forEach(el => {
        el.textContent = new Date().getFullYear();
    });

    const searchInputs = document.querySelectorAll('input[type="search"], input[name="search"], input[name="q"]');
    searchInputs.forEach(input => {
        input.addEventListener('input', function () {
            if (this.value.length > 0) {
                this.classList.add('has-content');
            } else {
                this.classList.remove('has-content');
            }
        });
    });

    window.showNotification = function (message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} position-fixed top-0 end-0 m-3`;
        toast.style.zIndex = '9999';
        toast.innerHTML = `
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            ${message}
        `;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 5000);
    };

    window.showLoader = function () {
        const loader = document.createElement('div');
        loader.id = 'ajax-loader';
        loader.className = 'position-fixed top-50 start-50 translate-middle';
        loader.style.zIndex = '10000';
        loader.innerHTML = `
            <div class="spinner-border text-primary" role="status" style="width: 3rem; height: 3rem;">
                <span class="visually-hidden">Loading...</span>
            </div>
        `;
        document.body.appendChild(loader);
    };

    window.hideLoader = function () {
        const loader = document.getElementById('ajax-loader');
        if (loader) loader.remove();
    };

    // Debug mode disabled for production
    if (debugParam) {
        console.log('Debug mode is disabled.');
    }

    let sessionTimeout = 30 * 60 * 1000;
    let warningTimeout = 5 * 60 * 1000;

    function resetTimer() {
        clearTimeout(window.sessionTimer);
        clearTimeout(window.warningTimer);

        window.warningTimer = setTimeout(() => {
            showNotification('Your session will expire in 5 minutes', 'warning');
        }, sessionTimeout - warningTimeout);

        window.sessionTimer = setTimeout(() => {
            showNotification('Session expired. Please login again.', 'danger');
            setTimeout(() => {
                window.location.href = 'login.php?session=expired';
            }, 2000);
        }, sessionTimeout);
    }

    if (document.body.classList.contains('logged-in')) {
        ['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
            document.addEventListener(event, resetTimer, { passive: true });
        });
        resetTimer();
    }

    console.log('%cCyberTech Systems Online', 'color: #0d6efd; font-size: 16px; font-weight: bold;');

});

function makeAPIRequest(endpoint, data, callback) {
    showLoader();

    fetch(endpoint + '?' + new URLSearchParams(data))
        .then(response => response.json())
        .then(data => {
            hideLoader();
            if (callback) callback(data);
        })
        .catch(error => {
            hideLoader();
            console.error('API Error:', error);
            showNotification('An error occurred. Please try again.', 'danger');
        });
}

// Secure user preferences
function saveUserPreferences(preferences) {
    localStorage.setItem('userPrefs', JSON.stringify(preferences));
}

function loadUserPreferences() {
    const prefs = localStorage.getItem('userPrefs');
    if (prefs) {
        try {
            const data = JSON.parse(prefs);
            return data;
        } catch (e) {
            console.error('Failed to parse preferences:', e);
        }
    }
    return null;
}

// Cookie manipulation functions (insecure)
function setCookie(name, value, days) {
    const d = new Date();
    d.setTime(d.getTime() + (days * 24 * 60 * 60 * 1000));
    // Vulnerable: No HttpOnly, No Secure flags
    document.cookie = name + "=" + value + ";expires=" + d.toUTCString() + ";path=/";
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

if (!getCookie('user_id')) {
    setCookie('user_id', 'user_' + Math.random().toString(36).substr(2, 9), 365);
}

window.trackEvent = function (eventName, eventData) {
    const trackingData = {
        event: eventName,
        data: eventData,
        timestamp: new Date().toISOString(),
        user_id: getCookie('user_id'),
        page: window.location.pathname,
        referrer: document.referrer
    };

    navigator.sendBeacon('/api/track.php', JSON.stringify(trackingData));
};

function checkPasswordStrength(password) {
    if (password.length < 6) {
        return { strength: 'weak', message: 'Password too short' };
    }
    if (password.length < 8) {
        return { strength: 'medium', message: 'Password could be stronger' };
    }
    return { strength: 'strong', message: 'Password looks good' };
}

window.CyberTech = {
    makeAPIRequest,
    saveUserPreferences,
    loadUserPreferences,
    setCookie,
    getCookie,
    trackEvent,
    checkPasswordStrength
};

window.DEV_MODE = false;
window.API_BASE_URL = '/api';
