document.addEventListener('DOMContentLoaded', function() {
    // Animation for elements when they come into view
    const animateOnScroll = function() {
        const elements = document.querySelectorAll('.feature-icon, h2, .card');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const windowHeight = window.innerHeight;
            
            if (elementPosition < windowHeight - 50) {
                element.classList.add('animated');
            }
        });
    };
    
    // Form validation enhancement
    const validateForms = function() {
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            form.addEventListener('submit', function(event) {
                if (!form.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                
                form.classList.add('was-validated');
            }, false);
        });
    };
    
    // Health rating selection enhancement
    const enhanceHealthRating = function() {
        const healthOptions = document.querySelectorAll('.health-option input');
        
        healthOptions.forEach(option => {
            option.addEventListener('change', function() {
                const selectedValue = this.value;
                console.log('Health rating selected:', selectedValue);
            });
        });
    };
    
    // Initialize functions
    window.addEventListener('scroll', animateOnScroll);
    validateForms();
    enhanceHealthRating();
    
    // Run initial animation check
    animateOnScroll();
});