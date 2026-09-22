/**
 * WebKids Academy - Main JavaScript
 * Gère la navigation, l'interface générale et les interactions
 */

// Menu mobile
document.addEventListener('DOMContentLoaded', function() {
  const btnMenu = document.querySelector('.btn-menu');
  const nav = document.querySelector('nav');

  if (btnMenu) {
    btnMenu.addEventListener('click', function() {
      nav.classList.toggle('active');
      btnMenu.classList.toggle('active');
    });
  }

  // Fermer le menu au clic sur un lien
  const navLinks = document.querySelectorAll('nav a');
  navLinks.forEach(link => {
    link.addEventListener('click', function() {
      nav.classList.remove('active');
      if (btnMenu) {
        btnMenu.classList.remove('active');
      }
    });
  });

  // Marqueur de page active
  setActiveNavLink();

  // Gestion des tabs
  initTabs();

  // Gestion des boutons copier
  initCopyButtons();

  // Smooth scroll pour les ancres
  initSmoothScroll();

  // Loader de code
  initCodeLoader();

  // Gestion de la sauvegarde de progression
  initProgressSave();
});

/**
 * Marque le lien de navigation actif
 */
function setActiveNavLink() {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const navLinks = document.querySelectorAll('nav a');

  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPage || (currentPage === '' && href === 'index.html')) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
}

/**
 * Initialise les tabs
 */
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', function() {
      const tabId = this.getAttribute('data-tab');

      // Désactiver tous les tabs
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      // Activer le tab cliqué
      this.classList.add('active');
      document.getElementById(tabId).classList.add('active');
    });
  });

  // Activer le premier tab par défaut
  const firstTab = document.querySelector('.tab-btn');
  if (firstTab) {
    firstTab.click();
  }
}

/**
 * Initialise les boutons copier
 */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll('.btn-copy');

  copyBtns.forEach(btn => {
    btn.addEventListener('click', function() {
      const codeBlock = this.closest('.code-block');
      const code = codeBlock.querySelector('code') || codeBlock.querySelector('pre');

      if (code) {
        const text = code.textContent;

        navigator.clipboard.writeText(text).then(() => {
          // Feedback visuel
          const originalText = this.textContent;
          this.textContent = 'Copié! ✓';
          this.classList.add('copied');

          setTimeout(() => {
            this.textContent = originalText;
            this.classList.remove('copied');
          }, 2000);
        }).catch(() => {
          alert('Erreur lors de la copie du code');
        });
      }
    });
  });
}

/**
 * Smooth scroll pour les ancres
 */
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();

      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
}

/**
 * Loader pour exécuter du code HTML/CSS
 */
function initCodeLoader() {
  const executeButtons = document.querySelectorAll('[data-execute="true"]');

  executeButtons.forEach(btn => {
    btn.addEventListener('click', function() {
      const codeBlock = this.closest('[data-code-container]');
      if (!codeBlock) return;

      const htmlCode = codeBlock.querySelector('[data-type="html"]')?.textContent || '';
      const cssCode = codeBlock.querySelector('[data-type="css"]')?.textContent || '';

      const preview = codeBlock.querySelector('[data-preview]');
      if (preview) {
        const output = htmlCode + (cssCode ? `<style>${cssCode}</style>` : '');
        preview.innerHTML = output;
      }
    });
  });
}

/**
 * Sauvegarde la progression dans localStorage
 */
function initProgressSave() {
  const progressElements = document.querySelectorAll('[data-progress]');

  progressElements.forEach(el => {
    const progressKey = el.getAttribute('data-progress');
    const savedValue = localStorage.getItem(progressKey);

    if (savedValue) {
      el.setAttribute('data-value', savedValue);
      updateProgressBar(el);
    }
  });
}

/**
 * Met à jour la barre de progression
 */
function updateProgressBar(element) {
  const value = parseFloat(element.getAttribute('data-value')) || 0;
  const progressBar = element.querySelector('.progress-fill');

  if (progressBar) {
    progressBar.style.width = value + '%';
  }
}

/**
 * Sauvegarde une progression
 */
function saveProgress(key, value) {
  localStorage.setItem(key, value);

  const element = document.querySelector(`[data-progress="${key}"]`);
  if (element) {
    element.setAttribute('data-value', value);
    updateProgressBar(element);
  }
}

/**
 * Récupère une progression
 */
function getProgress(key) {
  return localStorage.getItem(key) || 0;
}

/**
 * Ajoute une animation au scroll
 */
window.addEventListener('scroll', function() {
  const header = document.querySelector('header');

  if (window.scrollY > 10) {
    header.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.1)';
  } else {
    header.style.boxShadow = '0 1px 2px rgba(0, 0, 0, 0.05)';
  }
});

/**
 * Gestion des tooltips
 */
function showTooltip(element, message, duration = 3000) {
  const tooltip = document.createElement('div');
  tooltip.className = 'tooltip';
  tooltip.textContent = message;

  element.appendChild(tooltip);

  setTimeout(() => {
    tooltip.remove();
  }, duration);
}

/**
 * Convertir un pourcentage en couleur
 */
function getProgressColor(percentage) {
  if (percentage >= 75) return '#22C55E'; // Vert
  if (percentage >= 50) return '#F97316'; // Orange
  if (percentage >= 25) return '#F59E0B'; // Jaune
  return '#EF4444'; // Rouge
}

/**
 * Initialiser les badges de difficulté
 */
document.addEventListener('DOMContentLoaded', function() {
  const difficulties = {
    'beginner': { text: 'Débutant', color: '#22C55E' },
    'intermediate': { text: 'Intermédiaire', color: '#F97316' },
    'advanced': { text: 'Avancé', color: '#EF4444' }
  };

  document.querySelectorAll('[data-difficulty]').forEach(el => {
    const level = el.getAttribute('data-difficulty');
    if (difficulties[level]) {
      const info = difficulties[level];
      el.innerHTML = `
        <span style="display: inline-flex; align-items: center; gap: 0.5rem;">
          <span style="width: 12px; height: 12px; border-radius: 50%; background-color: ${info.color};"></span>
          ${info.text}
        </span>
      `;
    }
  });
});

/**
 * Quiz JavaScript
 */
class Quiz {
  constructor(container) {
    this.container = container;
    this.currentQuestion = 0;
    this.score = 0;
    this.answers = [];
  }

  init() {
    this.render();
  }

  render() {
    const questions = this.getQuestions();
    if (this.currentQuestion >= questions.length) {
      this.showResults();
      return;
    }

    const question = questions[this.currentQuestion];
    let html = `
      <div class="quiz-question">
        <h4>${question.question}</h4>
        <div class="quiz-options">
    `;

    question.options.forEach((option, index) => {
      html += `
        <label class="quiz-option">
          <input type="radio" name="answer" value="${index}" />
          <span>${option}</span>
        </label>
      `;
    });

    html += `
        </div>
        <button class="btn btn-primary" onclick="window.currentQuiz.next()">Suivant</button>
      </div>
    `;

    this.container.innerHTML = html;
  }

  next() {
    const selected = document.querySelector('input[name="answer"]:checked');
    if (!selected) {
      alert('Veuillez sélectionner une réponse');
      return;
    }

    const questions = this.getQuestions();
    const question = questions[this.currentQuestion];
    const answerIndex = parseInt(selected.value);

    this.answers.push({
      question: question.question,
      selected: question.options[answerIndex],
      correct: question.options[question.correctAnswer],
      isCorrect: answerIndex === question.correctAnswer
    });

    if (answerIndex === question.correctAnswer) {
      this.score++;
    }

    this.currentQuestion++;
    this.render();
  }

  showResults() {
    const questions = this.getQuestions();
    const percentage = Math.round((this.score / questions.length) * 100);

    let html = `
      <div class="quiz-results">
        <h3>Résultats du quiz</h3>
        <div style="text-align: center; margin: 2rem 0;">
          <div style="font-size: 3rem; font-weight: bold; color: #3B82F6;">
            ${this.score}/${questions.length}
          </div>
          <div style="font-size: 1.25rem; color: #666; margin-top: 0.5rem;">
            ${percentage}%
          </div>
        </div>
        <div class="quiz-review">
    `;

    this.answers.forEach((answer, index) => {
      const resultClass = answer.isCorrect ? 'correct' : 'incorrect';
      html += `
        <div class="quiz-review-item ${resultClass}">
          <strong>${index + 1}. ${answer.question}</strong>
          <p>Votre réponse: ${answer.selected}</p>
          ${!answer.isCorrect ? `<p>Bonne réponse: ${answer.correct}</p>` : ''}
        </div>
      `;
    });

    html += `
        </div>
        <button class="btn btn-primary" onclick="location.reload()">Recommencer</button>
      </div>
    `;

    this.container.innerHTML = html;
  }

  getQuestions() {
    // À implémenter par les pages qui utilisent le quiz
    return [];
  }
}

/**
 * Exporte les fonctions pour utilisation externe
 */
window.saveProgress = saveProgress;
window.getProgress = getProgress;
window.Quiz = Quiz;
window.showTooltip = showTooltip;
window.initCopyButtons = initCopyButtons;
