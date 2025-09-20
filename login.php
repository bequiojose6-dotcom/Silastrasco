<?php
// Start session with security settings
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include database connection
include 'connection.php';

// Initialize variables
$login_message = '';
$error = '';

// Handle GET messages
if (isset($_GET['message'])) {
    switch ($_GET['message']) {
        case 'auto_logout':
            $login_message = 'Auto-logged out due to inactivity';
            break;
        case 'session_expired':
            $login_message = 'Session expired. Please login again.';
            break;
        case 'logout':
            $login_message = 'You have been successfully logged out.';
            break;
        case 'login_required':
            $login_message = 'Please login to continue.';
            break;
    }
}

// Check request method
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // CSRF Protection
        if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            $error = "Invalid request. Please try again.";
        } else {
            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $remember_me = isset($_POST['remember']);

            // Input validation
            if (empty($email) || empty($password)) {
                $error = "Please fill in all fields.";
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = "Please enter a valid email address.";
            } elseif (strlen($password) < 6) {
                $error = "Password must be at least 6 characters long.";
            } else {
                // Check if database connection exists
                if (!isset($conn) || $conn->connect_error) {
                    $error = "Database connection error. Please try again later.";
                } else {
                    // Prepare statement with proper error handling
                    $stmt = $conn->prepare("SELECT userID, userType, fullname, password FROM users WHERE email = ?");
                    if (!$stmt) {
                        $error = "Database error. Please try again later.";
                    } else {
                        $stmt->bind_param("s", $email);
                        $stmt->execute();
                        $res = $stmt->get_result();

                        if ($res->num_rows === 1) {
                            $user = $res->fetch_assoc();

                            if ($user['userType'] === 'unverified') {
                                $error = "Please verify your email before logging in.";
                            } elseif (password_verify($password, $user['password'])) {
                                // Regenerate session ID for security
                                session_regenerate_id(true);
                                
                                // Set session variables
                                $_SESSION['user_id'] = $user['userID'];
                                $_SESSION['user_type'] = $user['userType'];
                                $_SESSION['fullname'] = $user['fullname'];
                                $_SESSION['login_time'] = time();
                                $_SESSION['last_activity'] = time();

                                // Handle remember me functionality
                                if ($remember_me) {
                                    $token = bin2hex(random_bytes(32));
                                    setcookie('remember_token', $token, time() + (30 * 24 * 60 * 60), '/', '', false, true); // 30 days
                                    // Store token in database (you'll need to add a remember_tokens table)
                                }

                                // Redirect based on user type
                                switch ($user['userType']) {
                                    case 'admin':
                                        header("Location: admindashboard.php");
                                        break;
                                    case 'driver':
                                        header("Location: driverdashboard.php");
                                        break;
                                    case 'passenger':
                                        header("Location: passengerdashboard.php");
                                        break;
                                    default:
                                        $error = "Unknown user type.";
                                        break;
                                }
                                exit();
                            } else {
                                $error = "Incorrect password.";
                            }
                        } else {
                            $error = "Email not found.";
                        }
                        $stmt->close();
                    }
                }
            }
        }
    } catch (Exception $e) {
        $error = "An error occurred. Please try again later.";
        error_log("Login error: " . $e->getMessage());
    }
}

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Set security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Silastrasco | Login</title>
    <link rel="stylesheet" href="Design/login.css"> 
    <link rel="icon" type="image/png" href="assets/Silastrasco-logo.png">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <!-- Animated Background Particles -->
    <div id="particles-js"></div>
    
    <nav class="navbar">
        <div class="nav-container">
            <a href="index.php" class="nav-brand">
                <img src="assets/Silastrasco-logo.png" alt="Silastrasco Logo" class="nav-logo-img">
                <span class="nav-logo-text">SILASTRASCO</span>
            </a>
            <div class="nav-actions">
                <a href="signup.php" class="btn secondary-btn">Sign Up</a>
            </div>
        </div>
    </nav>

    <main class="container">
        <!-- Left Side - Hero Section -->
        <section class="left-side">
            <div class="left-side-content">
                <h2>Your Jeepney Adventure Starts Here</h2>
                <p>Affordable and reliable jeepney transportation services</p>
                
                <div class="hero-features">
                    <div class="feature-card">
                        <i class="fas fa-shield-alt"></i>
                        <h4>Safe Rides</h4>
                        <p>Licensed drivers and well-maintained jeepneys</p>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-clock"></i>
                        <h4>On Schedule</h4>
                        <p>Regular routes with frequent trips</p>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-peso-sign"></i>
                        <h4>Budget-Friendly</h4>
                        <p>Affordable fares for everyone</p>
                    </div>
                </div>
            </div>
            
            <div class="hero-wave"></div>
        </section>

        <!-- Right Side - Form Section -->
        <section class="right-side">
            <div class="login-form-container">
                <div class="form-header">
                    <h1>Welcome     </h1>
                    <p>Log in to your Silastrasco account</p>
                </div>

                <?php if (!empty($error)) : ?>
                    <div class="error-message">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= htmlspecialchars($error) ?></span>
                    </div>
                <?php endif; ?>

                <?php if (!empty($login_message)) : ?>
                    <div class="success-message">
                        <i class="fas fa-check-circle"></i>
                        <span><?= htmlspecialchars($login_message) ?></span>
                    </div>
                <?php endif; ?>

                <form action="" method="POST" class="login-form" autocomplete="off" spellcheck="false">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <div class="input-with-icon">
                            <i class="fas fa-envelope"></i>
                            <input type="email" name="email" id="email" placeholder="Enter your email" required>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="password">Password</label>
                        <div class="input-with-icon">
                            <i class="fas fa-lock"></i>
                            <input type="password" name="password" id="password" placeholder="Enter your password" required>
                            <button type="button" class="toggle-password" aria-label="Show password">
                                <i class="far fa-eye"></i>
                            </button>
                        </div>
                    </div>

                    <div class="form-options">
                        <div class="remember-me">
                            <input type="checkbox" id="remember" name="remember">
                            <label for="remember">Remember me</label>
                        </div>
                        <a href="forgotpass.php" class="forgot-link">Forgot password?</a>
                    </div>

                    <button type="submit" class="btn primary-btn">
                        <span class="btn-text">Log In</span>
                    </button>

                    <div class="signup-redirect">
                        <p>Don't have an account? <a href="signup.php">Sign up</a></p>
                    </div>
                </form>
            </div>
        </section>
    </main>

    

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Password toggle functionality
            const togglePassword = document.querySelector('.toggle-password');
            const passwordInput = document.getElementById('password');
            
            if (togglePassword && passwordInput) {
                togglePassword.addEventListener('click', function() {
                    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                    passwordInput.setAttribute('type', type);
                    
                    // Toggle eye icon
                    const icon = this.querySelector('i');
                    if (icon) {
                        icon.classList.toggle('fa-eye');
                        icon.classList.toggle('fa-eye-slash');
                    }
                });
            }

            // Form validation and submission
            const loginForm = document.querySelector('.login-form');
            const emailInput = document.getElementById('email');
            const passwordInput = document.getElementById('password');
            
            if (loginForm) {
                // Real-time validation
                emailInput.addEventListener('blur', validateEmail);
                passwordInput.addEventListener('blur', validatePassword);
                
                loginForm.addEventListener('submit', function(e) {
                    // Clear previous error messages
                    clearErrorMessages();
                    
                    // Validate inputs
                    let isValid = true;
                    if (!validateEmail()) isValid = false;
                    if (!validatePassword()) isValid = false;
                    
                    if (!isValid) {
                        e.preventDefault();
                        return false;
                    }
                    
                    // Show loading state
                    const btn = this.querySelector('.primary-btn');
                    if (btn) {
                        btn.disabled = true;
                        const btnText = btn.querySelector('.btn-text');
                        if (btnText) btnText.textContent = 'Authenticating...';
                        
                        // Add spinner icon
                        const icon = document.createElement('i');
                        icon.className = 'fas fa-spinner fa-spin';
                        icon.style.marginLeft = '8px';
                        btn.appendChild(icon);
                    }
                    
                    // Allow form to submit naturally
                });
            }
            
            // Validation functions
            function validateEmail() {
                const email = emailInput.value.trim();
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                
                if (email === '') {
                    showFieldError(emailInput, 'Email is required');
                    return false;
                } else if (email.length > 255) {
                    showFieldError(emailInput, 'Email is too long');
                    return false;
                } else if (!emailRegex.test(email)) {
                    showFieldError(emailInput, 'Please enter a valid email address');
                    return false;
                } else {
                    clearFieldError(emailInput);
                    return true;
                }
            }
            
            function validatePassword() {
                const password = passwordInput.value;
                
                if (password === '') {
                    showFieldError(passwordInput, 'Password is required');
                    return false;
                } else if (password.length < 6) {
                    showFieldError(passwordInput, 'Password must be at least 6 characters');
                    return false;
                } else if (password.length > 128) {
                    showFieldError(passwordInput, 'Password is too long');
                    return false;
                } else {
                    clearFieldError(passwordInput);
                    return true;
                }
            }
            
            function showFieldError(input, message) {
                if (!input || !input.parentNode) return;
                
                clearFieldError(input);
                input.style.borderColor = 'var(--error-text)';
                input.style.boxShadow = '0 0 0 3px rgba(211, 47, 47, 0.2)';
                
                const errorDiv = document.createElement('div');
                errorDiv.className = 'field-error';
                errorDiv.style.color = 'var(--error-text)';
                errorDiv.style.fontSize = '0.8rem';
                errorDiv.style.marginTop = '0.25rem';
                errorDiv.style.display = 'flex';
                errorDiv.style.alignItems = 'center';
                errorDiv.style.gap = '0.25rem';
                errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle" style="font-size: 0.7rem;"></i>' + message;
                
                input.parentNode.appendChild(errorDiv);
            }
            
            function clearFieldError(input) {
                if (!input || !input.parentNode) return;
                
                input.style.borderColor = '';
                input.style.boxShadow = '';
                const errorDiv = input.parentNode.querySelector('.field-error');
                if (errorDiv) {
                    errorDiv.remove();
                }
            }
            
            function clearErrorMessages() {
                const errorMessages = document.querySelectorAll('.field-error');
                errorMessages.forEach(msg => msg.remove());
            }
            
            // Auto-hide success messages after 5 seconds
            const successMessage = document.querySelector('.success-message');
            if (successMessage) {
                setTimeout(() => {
                    successMessage.style.transition = 'opacity 0.3s ease';
                    successMessage.style.opacity = '0';
                    setTimeout(() => successMessage.remove(), 300);
                }, 5000);
            }
            
            // Auto-hide error messages after 8 seconds
            const errorMessage = document.querySelector('.error-message');
            if (errorMessage) {
                setTimeout(() => {
                    errorMessage.style.transition = 'opacity 0.3s ease';
                    errorMessage.style.opacity = '0';
                    setTimeout(() => errorMessage.remove(), 300);
                }, 8000);
            }
            
            // Add input focus effects
            const inputs = document.querySelectorAll('input[type="email"], input[type="password"]');
            inputs.forEach(input => {
                input.addEventListener('focus', function() {
                    this.parentNode.style.transform = 'scale(1.02)';
                });
                
                input.addEventListener('blur', function() {
                    this.parentNode.style.transform = 'scale(1)';
                });
            });
        });

        // Prevent back button
        history.pushState(null, null, location.href);
        window.onpopstate = function () {
            history.go(1);
        };
    </script>
</body>
</html>
