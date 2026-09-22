/**
 * WebKids Academy - Gestion des cours
 */

const courses = {
  html: [
    {
      id: 1,
      title: "Découvrir Internet et le Web",
      level: "beginner",
      module: 1,
      description: "Comprendre ce qu'est Internet et comment fonctionne le Web",
      duration: "10 min",
      objectives: [
        "Comprendre la différence entre Internet et le Web",
        "Découvrir ce qu'est une adresse URL",
        "Apprendre les bases du navigateur Web"
      ]
    },
    {
      id: 2,
      title: "Qu'est-ce qu'un site Web ?",
      level: "beginner",
      module: 2,
      description: "Découvrir la structure et les éléments d'un site Web",
      duration: "12 min",
      objectives: [
        "Identifier les éléments principaux d'une page Web",
        "Comprendre le rôle du serveur et du navigateur",
        "Découvrir le fonctionnement d'un site Web"
      ]
    },
    {
      id: 3,
      title: "Découvrir HTML",
      level: "beginner",
      module: 3,
      description: "Introduction à HTML, le langage de balisage du Web",
      duration: "15 min",
      objectives: [
        "Comprendre ce qu'est HTML",
        "Apprendre la syntaxe des balises",
        "Créer ta première balise HTML"
      ]
    },
    {
      id: 4,
      title: "Créer sa première page HTML",
      level: "beginner",
      module: 4,
      description: "Créer ta première page Web fonctionnelle",
      duration: "20 min",
      objectives: [
        "Créer une page HTML de base",
        "Comprendre la structure d'une page",
        "Utiliser les balises essentielles"
      ]
    },
    {
      id: 5,
      title: "Les titres et paragraphes",
      level: "beginner",
      module: 5,
      description: "Apprendre à utiliser les balises de texte",
      duration: "15 min",
      objectives: [
        "Utiliser les balises de titre (h1 à h6)",
        "Créer des paragraphes avec <p>",
        "Organiser le contenu texte"
      ]
    },
    {
      id: 6,
      title: "Insérer des images",
      level: "beginner",
      module: 6,
      description: "Ajouter des images à ta page Web",
      duration: "15 min",
      objectives: [
        "Utiliser la balise <img>",
        "Comprendre les attributs alt et src",
        "Redimensionner les images"
      ]
    },
    {
      id: 7,
      title: "Les liens hypertextes",
      level: "beginner",
      module: 7,
      description: "Créer des liens vers d'autres pages",
      duration: "15 min",
      objectives: [
        "Créer des liens avec <a>",
        "Comprendre les attributs href",
        "Lier des pages entre elles"
      ]
    },
    {
      id: 8,
      title: "Les listes",
      level: "beginner",
      module: 8,
      description: "Organiser le contenu avec des listes",
      duration: "15 min",
      objectives: [
        "Créer des listes non ordonnées",
        "Créer des listes ordonnées",
        "Créer des listes imbriquées"
      ]
    },
    {
      id: 9,
      title: "Les tableaux",
      level: "intermediate",
      module: 9,
      description: "Organiser les données avec des tableaux",
      duration: "20 min",
      objectives: [
        "Créer un tableau HTML",
        "Utiliser les balises tr, td, th",
        "Structurer les données"
      ]
    },
    {
      id: 10,
      title: "Créer une page personnelle",
      level: "intermediate",
      module: 10,
      description: "Projet final niveau débutant : créer ta page personnelle",
      duration: "30 min",
      objectives: [
        "Combiner les balises HTML",
        "Créer une page complète",
        "Publier ta première page"
      ]
    }
  ],

  css: [
    {
      id: 1,
      title: "Introduction à CSS",
      level: "beginner",
      module: 1,
      description: "Découvrir le CSS et comment styliser du HTML",
      duration: "15 min",
      objectives: [
        "Comprendre ce qu'est CSS",
        "Apprendre la syntaxe CSS",
        "Appliquer des styles à des éléments"
      ]
    },
    {
      id: 2,
      title: "Les sélecteurs CSS",
      level: "beginner",
      module: 2,
      description: "Maîtriser les sélecteurs CSS",
      duration: "20 min",
      objectives: [
        "Utiliser les sélecteurs de classe",
        "Utiliser les sélecteurs d'ID",
        "Utiliser les sélecteurs d'élément"
      ]
    },
    {
      id: 3,
      title: "Couleurs et arrière-plans",
      level: "beginner",
      module: 3,
      description: "Ajouter de la couleur à ta page Web",
      duration: "15 min",
      objectives: [
        "Utiliser les couleurs CSS",
        "Créer des arrière-plans",
        "Utiliser les gradients"
      ]
    },
    {
      id: 4,
      title: "Typographie CSS",
      level: "beginner",
      module: 4,
      description: "Personnaliser les textes",
      duration: "20 min",
      objectives: [
        "Changer la police de caractère",
        "Modifier la taille et le poids du texte",
        "Formater les textes"
      ]
    },
    {
      id: 5,
      title: "Le Box Model",
      level: "intermediate",
      module: 5,
      description: "Comprendre le modèle de boîte CSS",
      duration: "20 min",
      objectives: [
        "Comprendre margin et padding",
        "Utiliser les bordures",
        "Contrôler l'espacement"
      ]
    },
    {
      id: 6,
      title: "Flexbox",
      level: "intermediate",
      module: 6,
      description: "Créer des mises en page flexibles",
      duration: "30 min",
      objectives: [
        "Utiliser display: flex",
        "Aligner les éléments",
        "Créer des layouts complexes"
      ]
    },
    {
      id: 7,
      title: "CSS Grid",
      level: "intermediate",
      module: 7,
      description: "Créer des grilles avec CSS Grid",
      duration: "30 min",
      objectives: [
        "Utiliser display: grid",
        "Créer des colonnes et lignes",
        "Positionner les éléments"
      ]
    },
    {
      id: 8,
      title: "Transitions et animations",
      level: "advanced",
      module: 8,
      description: "Ajouter du mouvement à ta page",
      duration: "25 min",
      objectives: [
        "Créer des transitions CSS",
        "Utiliser les animations @keyframes",
        "Créer des effets interactifs"
      ]
    },
    {
      id: 9,
      title: "Responsive Design",
      level: "advanced",
      module: 9,
      description: "Adapter ta page à tous les appareils",
      duration: "30 min",
      objectives: [
        "Utiliser les media queries",
        "Créer un design responsive",
        "Tester sur différents appareils"
      ]
    },
    {
      id: 10,
      title: "Créer un site responsive",
      level: "advanced",
      module: 10,
      description: "Projet final : créer un site Web responsive",
      duration: "60 min",
      objectives: [
        "Combiner HTML et CSS",
        "Créer une mise en page responsive",
        "Publier un site professionnel"
      ]
    }
  ]
};

/**
 * Récupère un cours par ID et sujet
 */
function getCourse(subject, courseId) {
  const subjectCourses = courses[subject] || [];
  return subjectCourses.find(c => c.id === courseId);
}

/**
 * Récupère tous les cours d'un sujet
 */
function getCoursesBySubject(subject) {
  return courses[subject] || [];
}

/**
 * Récupère les cours par niveau
 */
function getCoursesByLevel(subject, level) {
  const subjectCourses = courses[subject] || [];
  return subjectCourses.filter(c => c.level === level);
}

/**
 * Récupère les cours non complétés
 */
function getUncompletedCourses(subject) {
  const subjectCourses = courses[subject] || [];
  return subjectCourses.filter(course => {
    const completed = localStorage.getItem(`course-${subject}-${course.id}`);
    return !completed;
  });
}

/**
 * Marque un cours comme complété
 */
function completeCourse(subject, courseId) {
  localStorage.setItem(`course-${subject}-${courseId}`, 'true');
  updateProgressBars(subject);
}

/**
 * Récupère le pourcentage de complétion
 */
function getCompletionPercentage(subject) {
  const subjectCourses = courses[subject] || [];
  if (subjectCourses.length === 0) return 0;

  const completed = subjectCourses.filter(course => {
    return localStorage.getItem(`course-${subject}-${course.id}`) === 'true';
  }).length;

  return Math.round((completed / subjectCourses.length) * 100);
}

/**
 * Met à jour les barres de progression
 */
function updateProgressBars(subject) {
  const percentage = getCompletionPercentage(subject);
  const bars = document.querySelectorAll(`[data-progress="${subject}"]`);

  bars.forEach(bar => {
    const fill = bar.querySelector('.progress-fill');
    if (fill) {
      fill.style.width = percentage + '%';
    }
  });
}

/**
 * Affiche les cours sur la page
 */
function renderCourses(containerId, subject, filterLevel = null) {
  const container = document.getElementById(containerId);
  if (!container) return;

  let coursesToShow = getCoursesBySubject(subject);

  if (filterLevel) {
    coursesToShow = coursesToShow.filter(c => c.level === filterLevel);
  }

  let html = '';

  coursesToShow.forEach(course => {
    const completed = localStorage.getItem(`course-${subject}-${course.id}`) === 'true';
    const completedClass = completed ? 'completed' : '';

    html += `
      <div class="card course-card ${completedClass}" data-course-id="${course.id}">
        <div class="card-header">
          <span>${course.title}</span>
          ${completed ? '<span style="color: #22C55E;">✓</span>' : ''}
        </div>
        <div class="card-body">
          <p>${course.description}</p>
          <div style="display: flex; gap: 1rem; justify-content: space-between; font-size: 0.875rem; color: #666; margin-top: 1rem;">
            <span data-difficulty="${course.level}"></span>
            <span>⏱ ${course.duration}</span>
          </div>
        </div>
        <div class="card-footer">
          <a href="cours.html?subject=${subject}&id=${course.id}" class="btn btn-primary btn-small">
            ${completed ? 'Revoir' : 'Commencer'}
          </a>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  // Initialiser les badges de difficulté
  document.querySelectorAll('[data-difficulty]').forEach(el => {
    const level = el.getAttribute('data-difficulty');
    const difficulties = {
      'beginner': { text: '🟢 Débutant', color: '#22C55E' },
      'intermediate': { text: '🟠 Intermédiaire', color: '#F97316' },
      'advanced': { text: '🔴 Avancé', color: '#EF4444' }
    };

    if (difficulties[level]) {
      el.textContent = difficulties[level].text;
    }
  });
}

/**
 * Exporte les fonctions
 */
window.getCourse = getCourse;
window.getCoursesBySubject = getCoursesBySubject;
window.getCoursesByLevel = getCoursesByLevel;
window.getUncompletedCourses = getUncompletedCourses;
window.completeCourse = completeCourse;
window.getCompletionPercentage = getCompletionPercentage;
window.updateProgressBars = updateProgressBars;
window.renderCourses = renderCourses;
