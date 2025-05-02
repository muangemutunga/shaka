// Wait for the DOM to load before running the script
document.addEventListener('DOMContentLoaded', function() {
    
    // Function to hide the loading overlay
    function hideLoadingOverlay() {
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) {
            // Adding a fade-out effect
            loadingOverlay.style.opacity = 0;
            setTimeout(function() {
                loadingOverlay.style.display = 'none';
            }, 500); // Matches the fade-out duration
        }
    }

    // Function to trigger successful submission
    function handleSuccess() {
        const successMessage = document.querySelector('.success-container p');
        successMessage.textContent = 'Your application has been successfully submitted! 🎉';
        
        const successButton = document.querySelector('.btn');
        successButton.textContent = 'Go to Home';
        successButton.setAttribute('href', '/'); // Link to home page
    }

    // Check if the loading overlay is present and hide it after 3 seconds
    setTimeout(function() {
        hideLoadingOverlay();
        handleSuccess();
    }, 3000); // Simulate a 3-second loading delay
    
    // Optional: Scroll back to the top of the page after success
    window.scrollTo(0, 0);

    // Ensure button's link points to home after success (already handled above in handleSuccess)

    // Optional: Add any future interaction logic (e.g., tracking button clicks, etc.)
    document.querySelector('.btn').addEventListener('click', function() {
        console.log('User clicked the success button!');
    });

    // For smooth scrolling on anchor links (in case you add anchors to navigate sections)
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    for (let link of anchorLinks) {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            window.scrollTo({
                top: targetElement.offsetTop,
                behavior: 'smooth'
            });
        });
    }

});


// Toggle mobile nav
document.addEventListener('DOMContentLoaded', function () {
    const burger = document.getElementById('burgerMenu');
    const navList = burger.querySelector('ul');

    burger.addEventListener('click', () => {
        navList.classList.toggle('active');
    });
});

