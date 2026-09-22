/**
 * WebKids Academy - Gestion de la progression et des badges
 */

const badges = [
  {
    id: 'first-course',
    name: 'Premier cours',
    description: 'Complète ton premier cours',
    icon: '🎓',
    condition: function() {
      return getCompletionPercentage('html') > 0 || getCompletionPercentage('css') > 0;
    }
  },
  {
    id: 'first-exercise',
    name: 'Premier exercice',
    description: 'Complète ton premier exercice',
    icon: '✍️',
    condition: function() {
      return getExercisesCompletionPercentage() > 0;
    }
  },
  {
    id: 'five-exercises',
    name: '5 exercices terminés',
    description: 'Complète 5 exercices',
    icon: '🚀',
    condition: function() {
      return getExercisesCompletionPercentage() >= 50;
    }
  },
  {
    id: 'html-expert',
    name: 'Expert HTML',
    description: 'Complète tous les cours HTML',
    icon: '🏆',
    condition: function() {
      return getCompletionPercentage('html') === 100;
    }
  },
  {
    id: 'css-expert',
    name: 'Expert CSS',
    description: 'Complète tous les cours CSS',
    icon: '✨',
    condition: function() {
      return getCompletionPercentage('css') === 100;
    }
  },
  {
    id: 'master',
    name: 'Master Web',
    description: 'Maîtrise le HTML et le CSS',
    icon: '👑',
    condition: function() {
      return getCompletionPercentage('html') === 100 && getCompletionPercentage('css') === 100;
    }
  }
];

/**
 * Récupère les badges débloqués
 */
function getUnlockedBadges() {
  return badges.filter(badge => {
    const unlocked = localStorage.getItem(`badge-${badge.id}`);
    return unlocked === 'true' || badge.condition();
  });
}

/**
 * Déverrouille un badge
 */
function unlockBadge(badgeId) {
  const badge = badges.find(b => b.id === badgeId);
  if (badge && !localStorage.getItem(`badge-${badgeId}`)) {
    localStorage.setItem(`badge-${badgeId}`, 'true');
    showBadgeNotification(badge);
  }
}

/**
 * Affiche une notification de badge
 */
function showBadgeNotification(badge) {
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: linear-gradient(135deg, #3B82F6 0%, #9333EA 100%);
    color: white;
    padding: 1.5rem;
    border-radius: 1rem;
    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
    z-index: 9999;
    animation: slideInUp 0.5s ease-in-out;
    max-width: 300px;
  `;

  notification.innerHTML = `
    <div style="font-size: 2rem; margin-bottom: 0.5rem;">${badge.icon}</div>
    <strong>${badge.name}</strong>
    <p style="font-size: 0.875rem; margin-top: 0.5rem;">${badge.description}</p>
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.animation = 'fadeOut 0.5s ease-in-out';
    setTimeout(() => notification.remove(), 500);
  }, 4000);
}

/**
 * Affiche les badges
 */
function renderBadges(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const unlockedBadges = getUnlockedBadges();
  const lockedBadgesCount = badges.length - unlockedBadges.length;

  let html = `
    <div style="margin-bottom: 2rem;">
      <h3>Tes Badges (${unlockedBadges.length}/${badges.length})</h3>
      <div class="grid grid-4" style="margin-top: 1.5rem;">
  `;

  // Badges débloqués
  unlockedBadges.forEach(badge => {
    html += `
      <div class="badge-item" style="text-align: center; padding: 1.5rem; background: white; border-radius: 1rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border: 2px solid #22C55E;">
        <div style="font-size: 3rem; margin-bottom: 0.5rem;">${badge.icon}</div>
        <strong style="display: block; margin-bottom: 0.25rem;">${badge.name}</strong>
        <small style="color: #666;">${badge.description}</small>
      </div>
    `;
  });

  // Badges verrouillés
  badges.filter(b => !unlockedBadges.find(ub => ub.id === b.id)).forEach(badge => {
    html += `
      <div class="badge-item" style="text-align: center; padding: 1.5rem; background: #f5f5f5; border-radius: 1rem; opacity: 0.5; border: 2px solid #ddd;">
        <div style="font-size: 3rem; margin-bottom: 0.5rem; filter: grayscale(1);">🔒</div>
        <strong style="display: block; margin-bottom: 0.25rem;">${badge.name}</strong>
        <small style="color: #999;">${badge.description}</small>
      </div>
    `;
  });

  html += `
      </div>
    </div>
  `;

  container.innerHTML = html;
}

/**
 * Calcule et affiche la progression globale
 */
function renderProgress(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const htmlPercent = getCompletionPercentage('html');
  const cssPercent = getCompletionPercentage('css');
  const exercisesPercent = getExercisesCompletionPercentage();
  const globalPercent = Math.round((htmlPercent + cssPercent + exercisesPercent) / 3);

  let html = `
    <div class="progress-section">
      <h3>Ma Progression</h3>

      <div style="margin-top: 2rem;">
        <div class="progress-container" style="margin-bottom: 2rem;">
          <div class="progress-label">
            <span>HTML5</span>
            <span>${htmlPercent}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${htmlPercent}%;" data-progress="html"></div>
          </div>
        </div>

        <div class="progress-container" style="margin-bottom: 2rem;">
          <div class="progress-label">
            <span>CSS3</span>
            <span>${cssPercent}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${cssPercent}%;"></div>
          </div>
        </div>

        <div class="progress-container" style="margin-bottom: 2rem;">
          <div class="progress-label">
            <span>Exercices</span>
            <span>${exercisesPercent}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${exercisesPercent}%;"></div>
          </div>
        </div>

        <div class="progress-container" style="padding: 1.5rem; background: linear-gradient(135deg, #3B82F6 0%, #9333EA 100%); border-radius: 1rem; color: white;">
          <div class="progress-label" style="color: white; font-weight: bold;">
            <span>Progression globale</span>
            <span>${globalPercent}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${globalPercent}%;"></div>
          </div>
        </div>
      </div>
    </div>
  `;

  container.innerHTML = html;
}

/**
 * Affiche un résumé de la progression
 */
function renderProgressSummary(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const htmlPercent = getCompletionPercentage('html');
  const cssPercent = getCompletionPercentage('css');
  const exercisesPercent = getExercisesCompletionPercentage();
  const globalPercent = Math.round((htmlPercent + cssPercent + exercisesPercent) / 3);
  const unlockedBadges = getUnlockedBadges();

  let html = `
    <div class="card">
      <div class="card-header">
        <span>📊 Ton Résumé</span>
      </div>
      <div class="card-body">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
          <div style="text-align: center; padding: 1rem; background: #f0f9ff; border-radius: 0.5rem;">
            <div style="font-size: 2rem; font-weight: bold; color: #3B82F6;">${globalPercent}%</div>
            <div style="color: #666; font-size: 0.875rem;">Progression globale</div>
          </div>
          <div style="text-align: center; padding: 1rem; background: #f0fdf4; border-radius: 0.5rem;">
            <div style="font-size: 2rem; font-weight: bold; color: #22C55E;">${unlockedBadges.length}</div>
            <div style="color: #666; font-size: 0.875rem;">Badges débloqués</div>
          </div>
        </div>
      </div>
    </div>
  `;

  container.innerHTML = html;
}

/**
 * Affiche les statistiques
 */
function renderStatistics(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const totalCourses = getCoursesBySubject('html').length + getCoursesBySubject('css').length;
  const completedCourses = getCoursesBySubject('html').filter(c =>
    localStorage.getItem(`course-html-${c.id}`) === 'true'
  ).length + getCoursesBySubject('css').filter(c =>
    localStorage.getItem(`course-css-${c.id}`) === 'true'
  ).length;

  const totalExercises = window.exercises ? window.exercises.length : 0;
  const completedExercises = totalExercises ? totalExercises * getExercisesCompletionPercentage() / 100 : 0;

  let html = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 2rem;">
      <div class="card">
        <div class="card-header">📚 Cours</div>
        <div class="card-body" style="text-align: center;">
          <div style="font-size: 2rem; font-weight: bold; color: #3B82F6;">${completedCourses}/${totalCourses}</div>
          <div style="color: #666; margin-top: 0.5rem;">Cours terminés</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">✍️ Exercices</div>
        <div class="card-body" style="text-align: center;">
          <div style="font-size: 2rem; font-weight: bold; color: #9333EA;">${Math.round(completedExercises)}/${totalExercises}</div>
          <div style="color: #666; margin-top: 0.5rem;">Exercices complétés</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">🏆 Badges</div>
        <div class="card-body" style="text-align: center;">
          <div style="font-size: 2rem; font-weight: bold; color: #EC4899;">${getUnlockedBadges().length}/${badges.length}</div>
          <div style="color: #666; margin-top: 0.5rem;">Badges débloqués</div>
        </div>
      </div>
    </div>
  `;

  container.innerHTML = html;
}

/**
 * Réinitialise la progression (pour tests)
 */
function resetProgress() {
  if (confirm('Êtes-vous sûr? Cela réinitialisera toute votre progression.')) {
    const keys = Object.keys(localStorage);
    keys.forEach(key => {
      if (key.startsWith('course-') || key.startsWith('exercise-') || key.startsWith('badge-')) {
        localStorage.removeItem(key);
      }
    });
    location.reload();
  }
}

/**
 * Vérifie et déverrouille les badges
 */
function checkAndUnlockBadges() {
  badges.forEach(badge => {
    if (badge.condition()) {
      unlockBadge(badge.id);
    }
  });
}

// Vérifie les badges au chargement
document.addEventListener('DOMContentLoaded', checkAndUnlockBadges);

/**
 * Exporte les fonctions
 */
window.getUnlockedBadges = getUnlockedBadges;
window.unlockBadge = unlockBadge;
window.renderBadges = renderBadges;
window.renderProgress = renderProgress;
window.renderProgressSummary = renderProgressSummary;
window.renderStatistics = renderStatistics;
window.resetProgress = resetProgress;
window.checkAndUnlockBadges = checkAndUnlockBadges;
