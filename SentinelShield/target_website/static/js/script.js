// Dark mode toggle
function toggleDarkMode() {
    document.body.classList.toggle("dark-mode");
    // Optional: save preference in local storage
    if (document.body.classList.contains('dark-mode')) {
        localStorage.setItem('theme', 'dark');
    } else {
        localStorage.setItem('theme', 'light');
    }
}

// Check for saved theme preference
document.addEventListener('DOMContentLoaded', () => {
    if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark-mode');
    }

    // Initialize scroll animations and back-to-top button
    initializeUxFeatures();
});

// Loader animation
window.addEventListener("load", function () {
    const spinner = document.querySelector(".spinner-wrapper");
    spinner.style.opacity = '0';
    setTimeout(() => {
        spinner.style.display = "none";
    }, 500); // Match transition time in CSS
});


function initializeUxFeatures() {
    // Animate on scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1
    });

    document.querySelectorAll('.feature-card, .team-member, .use-case-card').forEach(el => {
        observer.observe(el);
    });

    // Back to top button
    const backToTopButton = document.createElement('button');
    backToTopButton.innerText = '↑';
    backToTopButton.className = 'back-to-top';
    document.body.appendChild(backToTopButton);

    window.addEventListener('scroll', () => {
        if (window.scrollY > 300) {
            backToTopButton.classList.add('visible');
        } else {
            backToTopButton.classList.remove('visible');
        }
    });

    backToTopButton.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
}