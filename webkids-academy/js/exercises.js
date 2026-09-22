/**
 * WebKids Academy - Gestion des exercices
 */

const exercises = [
  // Exercices HTML débutant
  {
    id: 1,
    category: "html-beginner",
    difficulty: "beginner",
    title: "Créer un titre principal",
    description: "Crée un titre de niveau 1 contenant le texte : 'Mon premier site'",
    hint: "Utilise la balise &lt;h1&gt; et ferme-la avec &lt;/h1&gt;",
    expectedOutput: `<h1>Mon premier site</h1>`,
    solution: `<h1>Mon premier site</h1>`,
    explanation: "La balise <h1> crée le titre le plus important d'une page. Elle doit toujours être fermée."
  },
  {
    id: 2,
    category: "html-beginner",
    difficulty: "beginner",
    title: "Créer un paragraphe",
    description: "Crée un paragraphe avec le texte : 'Bienvenue sur mon site Web'",
    hint: "Utilise la balise &lt;p&gt; pour créer un paragraphe",
    expectedOutput: `<p>Bienvenue sur mon site Web</p>`,
    solution: `<p>Bienvenue sur mon site Web</p>`,
    explanation: "La balise <p> crée un paragraphe. C'est l'élément le plus courant pour du texte."
  },
  {
    id: 3,
    category: "html-beginner",
    difficulty: "beginner",
    title: "Créer une liste non ordonnée",
    description: "Crée une liste avec trois éléments : 'HTML', 'CSS', 'JavaScript'",
    hint: "Utilise &lt;ul&gt; pour la liste et &lt;li&gt; pour chaque élément",
    expectedOutput: `<ul>
  <li>HTML</li>
  <li>CSS</li>
  <li>JavaScript</li>
</ul>`,
    solution: `<ul>
  <li>HTML</li>
  <li>CSS</li>
  <li>JavaScript</li>
</ul>`,
    explanation: "La balise <ul> crée une liste non ordonnée (avec des points). Chaque élément utilise <li>."
  },
  {
    id: 4,
    category: "html-beginner",
    difficulty: "beginner",
    title: "Créer un lien",
    description: "Crée un lien vers 'https://www.google.com' avec le texte 'Google'",
    hint: "Utilise la balise &lt;a&gt; avec l'attribut href",
    expectedOutput: `<a href="https://www.google.com">Google</a>`,
    solution: `<a href="https://www.google.com">Google</a>`,
    explanation: "La balise <a> crée un lien hypertexte. L'attribut href indique la destination."
  },
  {
    id: 5,
    category: "html-beginner",
    difficulty: "beginner",
    title: "Insérer une image",
    description: "Insère une image avec la source 'photo.jpg' et le texte alternatif 'Ma photo'",
    hint: "Utilise la balise &lt;img&gt; avec les attributs src et alt",
    expectedOutput: `<img src="photo.jpg" alt="Ma photo">`,
    solution: `<img src="photo.jpg" alt="Ma photo">`,
    explanation: "La balise <img> insère une image. src indique le chemin, alt le texte si l'image ne charge pas."
  },

  // Exercices HTML intermédiaire
  {
    id: 6,
    category: "html-intermediate",
    difficulty: "intermediate",
    title: "Structure d'une page HTML5",
    description: "Crée la structure complète d'une page HTML5 avec une en-tête, contenu principal et pied de page",
    hint: "Utilise &lt;header&gt;, &lt;main&gt; et &lt;footer&gt;",
    expectedOutput: `<header>
  <h1>Mon Site</h1>
</header>
<main>
  <section>
    <p>Contenu principal</p>
  </section>
</main>
<footer>
  <p>Pied de page</p>
</footer>`,
    solution: `<header>
  <h1>Mon Site</h1>
</header>
<main>
  <section>
    <p>Contenu principal</p>
  </section>
</main>
<footer>
  <p>Pied de page</p>
</footer>`,
    explanation: "La structure HTML5 sémantique utilise des balises spécifiques pour organiser le contenu."
  },

  // Exercices CSS débutant
  {
    id: 7,
    category: "css-beginner",
    difficulty: "beginner",
    title: "Changer la couleur d'un texte",
    description: "Crée une règle CSS pour que le texte soit bleu",
    hint: "Utilise la propriété color: blue;",
    expectedOutput: `p {
  color: blue;
}`,
    solution: `p {
  color: blue;
}`,
    explanation: "La propriété 'color' change la couleur du texte. On peut utiliser des noms de couleurs ou des codes hex."
  },
  {
    id: 8,
    category: "css-beginner",
    difficulty: "beginner",
    title: "Changer la taille du texte",
    description: "Crée une règle CSS pour que les titres h2 fassent 32 pixels",
    hint: "Utilise font-size: 32px;",
    expectedOutput: `h2 {
  font-size: 32px;
}`,
    solution: `h2 {
  font-size: 32px;
}`,
    explanation: "La propriété 'font-size' contrôle la taille du texte. 32px signifie 32 pixels."
  },
  {
    id: 9,
    category: "css-beginner",
    difficulty: "beginner",
    title: "Ajouter une couleur de fond",
    description: "Crée une règle CSS pour que le fond soit jaune",
    hint: "Utilise background-color: yellow;",
    expectedOutput: `body {
  background-color: yellow;
}`,
    solution: `body {
  background-color: yellow;
}`,
    explanation: "La propriété 'background-color' change la couleur de fond d'un élément."
  },

  // Exercices CSS intermédiaire
  {
    id: 10,
    category: "css-intermediate",
    difficulty: "intermediate",
    title: "Utiliser des marges et espaces",
    description: "Ajoute une marge de 20px autour d'une div et 10px de padding à l'intérieur",
    hint: "Utilise margin et padding",
    expectedOutput: `div {
  margin: 20px;
  padding: 10px;
}`,
    solution: `div {
  margin: 20px;
  padding: 10px;
}`,
    explanation: "Margin crée l'espace autour, padding l'espace à l'intérieur. C'est le Box Model."
  },
  {
    id: 11,
    category: "css-intermediate",
    difficulty: "intermediate",
    title: "Créer une bordure",
    description: "Crée une bordure solide de 2px bleue autour d'une div",
    hint: "Utilise border: 2px solid blue;",
    expectedOutput: `div {
  border: 2px solid blue;
}`,
    solution: `div {
  border: 2px solid blue;
}`,
    explanation: "La propriété 'border' ajoute une bordure. Format: épaisseur, style, couleur."
  },
];

/**
 * Récupère un exercice par ID
 */
function getExercise(exerciseId) {
  return exercises.find(e => e.id === exerciseId);
}

/**
 * Récupère les exercices par catégorie
 */
function getExercisesByCategory(category) {
  return exercises.filter(e => e.category === category);
}

/**
 * Récupère les exercices non complétés
 */
function getUncompletedExercises() {
  return exercises.filter(exercise => {
    const completed = localStorage.getItem(`exercise-${exercise.id}`);
    return !completed;
  });
}

/**
 * Marque un exercice comme complété
 */
function completeExercise(exerciseId) {
  localStorage.setItem(`exercise-${exerciseId}`, 'true');
}

/**
 * Récupère le pourcentage de complétion des exercices
 */
function getExercisesCompletionPercentage() {
  const totalExercises = exercises.length;
  if (totalExercises === 0) return 0;

  const completed = exercises.filter(e => {
    return localStorage.getItem(`exercise-${e.id}`) === 'true';
  }).length;

  return Math.round((completed / totalExercises) * 100);
}

/**
 * Vérifie la réponse de l'utilisateur
 */
function checkAnswer(exerciseId, userAnswer) {
  const exercise = getExercise(exerciseId);
  if (!exercise) return { correct: false, message: 'Exercice non trouvé' };

  // Normaliser les réponses
  const normalize = (str) => {
    return str
      .trim()
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .replace(/>\s+</g, '><');
  };

  const userNormalized = normalize(userAnswer);
  const expectedNormalized = normalize(exercise.solution);

  if (userNormalized === expectedNormalized) {
    completeExercise(exerciseId);
    return {
      correct: true,
      message: '✓ Bonne réponse! Bien joué!',
      solution: exercise.solution,
      explanation: exercise.explanation
    };
  }

  return {
    correct: false,
    message: '✗ Pas encore... Relire l\'indice et réessaie!',
    hint: exercise.hint,
    solution: exercise.solution,
    explanation: exercise.explanation
  };
}

/**
 * Affiche les exercices sur la page
 */
function renderExercises(containerId, category = null) {
  const container = document.getElementById(containerId);
  if (!container) return;

  let exercisesToShow = category ? getExercisesByCategory(category) : exercises;

  let html = '';

  exercisesToShow.forEach(exercise => {
    const completed = localStorage.getItem(`exercise-${exercise.id}`) === 'true';
    const completedClass = completed ? 'completed' : '';

    html += `
      <div class="card exercise-card ${completedClass}" data-exercise-id="${exercise.id}">
        <div class="card-header">
          <span>${exercise.title}</span>
          ${completed ? '<span style="color: #22C55E;">✓</span>' : ''}
        </div>
        <div class="card-body">
          <p>${exercise.description}</p>
          <div style="margin-top: 1rem;">
            <span data-difficulty="${exercise.difficulty}"></span>
          </div>
        </div>
        <div class="card-footer">
          <a href="#" class="btn btn-primary btn-small" onclick="startExercise(${exercise.id}); return false;">
            Commencer
          </a>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

/**
 * Démarre un exercice (affiche le formulaire)
 */
function startExercise(exerciseId) {
  const exercise = getExercise(exerciseId);
  if (!exercise) return;

  const modal = document.createElement('div');
  modal.className = 'exercise-modal';
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: rgba(0,0,0,0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  `;

  modal.innerHTML = `
    <div style="background: white; padding: 2rem; border-radius: 1rem; max-width: 600px; max-height: 90vh; overflow-y: auto;">
      <h3>${exercise.title}</h3>
      <p>${exercise.description}</p>

      <div style="margin: 2rem 0; padding: 1rem; background: #f0f9ff; border-radius: 0.5rem;">
        <strong>Résultat attendu:</strong>
        <div style="margin-top: 0.5rem; font-family: monospace; background: #fff; padding: 0.5rem; border-radius: 0.25rem; overflow-x: auto;">
          ${exercise.expectedOutput.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
        </div>
      </div>

      <label>Écris ton code:</label>
      <textarea id="exercise-answer" style="width: 100%; height: 150px; padding: 0.5rem; border: 1px solid #ddd; border-radius: 0.25rem; font-family: monospace;"></textarea>

      <div style="margin-top: 1rem; display: flex; gap: 0.5rem;">
        <button class="btn btn-primary" onclick="submitExercise(${exerciseId})">Vérifier</button>
        <button class="btn btn-secondary" onclick="this.closest('.exercise-modal').remove()">Fermer</button>
      </div>

      <button class="btn btn-secondary btn-small" onclick="showExerciseHint(${exerciseId})">Afficher l'indice</button>
      <button class="btn btn-secondary btn-small" onclick="showExerciseSolution(${exerciseId})">Voir la solution</button>
    </div>
  `;

  document.body.appendChild(modal);
  document.getElementById('exercise-answer').focus();
}

/**
 * Envoie la réponse de l'exercice
 */
function submitExercise(exerciseId) {
  const answer = document.getElementById('exercise-answer')?.value || '';
  const result = checkAnswer(exerciseId, answer);

  const resultDiv = document.querySelector('.exercise-modal') ?
    document.querySelector('.exercise-modal') : null;

  if (resultDiv) {
    alert(result.message + (result.correct ? '\n\n' + result.explanation : ''));
    if (result.correct) {
      resultDiv.remove();
    }
  }
}

/**
 * Affiche l'indice
 */
function showExerciseHint(exerciseId) {
  const exercise = getExercise(exerciseId);
  if (exercise) {
    alert('Indice: ' + exercise.hint);
  }
}

/**
 * Affiche la solution
 */
function showExerciseSolution(exerciseId) {
  const exercise = getExercise(exerciseId);
  if (exercise) {
    alert('Solution:\n\n' + exercise.solution + '\n\nExplication: ' + exercise.explanation);
  }
}

/**
 * Exporte les fonctions
 */
window.getExercise = getExercise;
window.getExercisesByCategory = getExercisesByCategory;
window.getUncompletedExercises = getUncompletedExercises;
window.completeExercise = completeExercise;
window.getExercisesCompletionPercentage = getExercisesCompletionPercentage;
window.checkAnswer = checkAnswer;
window.renderExercises = renderExercises;
window.startExercise = startExercise;
window.submitExercise = submitExercise;
window.showExerciseHint = showExerciseHint;
window.showExerciseSolution = showExerciseSolution;
