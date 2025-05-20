import React, { useState } from 'react';
import './App.css';




const AuthFlow = () => {
    // Main state
    const [activeTab, setActiveTab] = useState('signup');
    const [currentStep, setCurrentStep] = useState(1);
    const [authFlow, setAuthFlow] = useState('main'); // main, forgot-password, verify-email, reset-password
    const [verificationCode, setVerificationCode] = useState(['', '', '', '', '', '']);
  
    // Form data
    const [formData, setFormData] = useState({
      // Signup steps
      fullName: '',
      email: '',
      startupName: '',
      phone: '',
      startupEmail: '',
      industry: '',
      location: '',
      description: '',
      businessType: '',
      commercialRegister: '',
      password: '',
      confirmPassword: '',
      // Login
      loginEmail: '',
      loginPassword: '',
      rememberMe: false,
      // Password reset
      newPassword: '',
      confirmNewPassword: ''
    });
  
    // Handle tab change
    const handleTabChange = (tab) => {
      setActiveTab(tab);
      setCurrentStep(1);
      setAuthFlow('main');
    };
  
    // Handle input changes
    const handleInputChange = (e) => {
      const { name, value, type, checked } = e.target;
      setFormData(prev => ({
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      }));
    };
  
    // Handle verification code input
    const handleVerificationCodeChange = (e, index) => {
      const newCode = [...verificationCode];
      newCode[index] = e.target.value;
      setVerificationCode(newCode);
      
      // Auto focus to next input
      if (e.target.value && index < 5) {
        document.getElementById(`verification-code-${index + 1}`).focus();
      }
    };
  
    // Navigation functions
    const nextStep = () => setCurrentStep(prev => prev + 1);
    const prevStep = () => setCurrentStep(prev => prev - 1);
    const startForgotPassword = () => setAuthFlow('forgot-password');
    const startEmailVerification = () => setAuthFlow('verify-email');
    const startPasswordReset = () => setAuthFlow('reset-password');
    const backToLogin = () => setAuthFlow('main');
  
    // Form submission handlers
    const handleSignupSubmit = (e) => {
      e.preventDefault();
      console.log('Signup submitted:', formData);
      // Handle signup logic
    };
  
    const handleLoginSubmit = (e) => {
      e.preventDefault();
      console.log('Login submitted:', {
        email: formData.loginEmail,
        password: formData.loginPassword,
        rememberMe: formData.rememberMe
      });
      // Handle login logic
    };
  
    const handleForgotPasswordSubmit = (e) => {
      e.preventDefault();
      console.log('Password reset requested for:', formData.loginEmail);
      startEmailVerification();
      // Handle forgot password logic
    };
  
    const handleVerifyEmailSubmit = (e) => {
      e.preventDefault();
      console.log('Verification code submitted:', verificationCode.join(''));
      startPasswordReset();
      // Handle verification logic
    };
  
    const handlePasswordResetSubmit = (e) => {
      e.preventDefault();
      console.log('Password reset with:', formData.newPassword);
      backToLogin();
      // Handle password reset logic
    };
  
    // Render signup steps
    const renderSignupStep = () => {
      switch (currentStep) {
        case 1:
          return (
            <>
              <div className="wlcm">
                <h1>Welcome</h1>
                <h2>Create your account</h2>
                <p>First enter your personal information</p>
              </div>
              <div className="form-group">
                <input
                  type="text"
                  name="fullName"
                  placeholder="Enter your full name"
                  value={formData.fullName}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <select
                  name="gender"
                  value={formData.gender}
                  onChange={handleInputChange}
                  required
                >
                  <option value="">Select your gender</option>
                  <option value="Male">Male</option>
                  <option value="Female">Female</option>
                  
                  {/* Add more locations */}
                </select>
              </div>
              <div className="form-group">
                <input
                  type="text"
                  name="date"
                  placeholder="Enter your date of birth "
                  value={formData.date}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div >
                <button className="next" type="button" onClick={nextStep}>Next →</button>
              </div>
            </>
          );
        
        case 2:
          return (
            <>
              <h1>Welcome</h1>
              <h2>Create your account</h2>
              <p>Second enter your startup's information</p>
              
              <div className="form-group">
                <input
                  type="text"
                  name="startupName"
                  placeholder="Enter your startup's name"
                  value={formData.startupName}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <input
                  type="tel"
                  name="phone"
                  placeholder="Enter your startup's phone number"
                  value={formData.phone}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <input
                  type="email"
                  name="startupEmail"
                  placeholder="Enter your startup's email"
                  value={formData.startupEmail}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <input
                  type="text"
                  name="industry"
                  placeholder="Enter your startup's industry"
                  value={formData.industry}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <select
                  name="location"
                  value={formData.location}
                  onChange={handleInputChange}
                  required
                >
                  <option value="">Select location (Wilaya) of your startup</option>
                  <option value="Algiers">Algiers</option>
                  <option value="Oran">Oran</option>
                  <option value="Constantine">Constantine</option>
                  {/* Add more locations */}
                </select>
              </div>
              
              <div className="form-group">
                <textarea
                  name="description"
                  placeholder="Write a description about your startup"
                  value={formData.description}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="button-group">
                <button className="back" type="button" onClick={prevStep}>← Back</button>
                <button className="next2" type="button" onClick={nextStep}>Next →</button>
              </div>
            </>
          );
        
        case 3:
          return (
            <>
              <div className="register">
                <h1>Welcome</h1>
                <h2>Create your account</h2>
                <p>Third enter your business registration or commercial register</p>
              </div>
              <div class="file-upload-container">
                <div class="file-upload-box">
                  <svg class="upload-icon" viewBox="0 0 24 24">
                    <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
                  </svg>
                  <p class="upload-instruction">Drag and Drop here</p>
                  <p class="upload-or">or</p>
                  <label for="file-input" class="browse-button">Browse file</label>
                  <input type="file" id="file-input" accept=".doc,.docx" />
                  
                </div>
                
              </div>
              <p class="file-restriction">Accepted file types: .doc and .docx only</p>
              <div className="button-group">
                <button className="back1" type="button" onClick={prevStep}>← Back</button>
                <button className="next3" type="button" onClick={nextStep}>Next →</button>
              </div>
            </>
          );
        
        case 4:
          return (
            <>
              <h1>Welcome</h1>
              <h2>Create your account</h2>
              <p>Last create a password to your account</p>
              
              <div className="form-group">
                <input
                  type="password"
                  name="password"
                  placeholder="Write a password"
                  value={formData.password}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="form-group">
                <input
                  type="password"
                  name="confirmPassword"
                  placeholder="Confirm your password"
                  value={formData.confirmPassword}
                  onChange={handleInputChange}
                  required
                />
              </div>
              
              <div className="checkbox-group">
                <input
                  type="checkbox"
                  id="terms"
                  name="terms"
                  required
                />
                <label htmlFor="terms">I agree to the Terms and Conditions and Privacy Policy</label>
              </div>
              
              <div className="button-group">
                <button className="back2" type="button" onClick={prevStep}>← Back</button>
                <button className="signup" type="submit">Sign Up</button>
              </div>
            </>
          );
        
        default:
          return null;
      }
    };
  
    // Render login form
    const renderLoginForm = () => (
      <>
        <h1>Welcome Back</h1>
        <h2>Startup log in</h2>
        
        <div className="form-group">
          <input
            type="email"
            name="loginEmail"
            placeholder="Enter your startup's email"
            value={formData.loginEmail}
            onChange={handleInputChange}
            required
          />
        </div>
        
        <div className="form-group">
          <input
            type="password"
            name="loginPassword"
            placeholder="Enter your password"
            value={formData.loginPassword}
            onChange={handleInputChange}
            required
          />
        </div>
        
        <div className="login-options">
          <div className="checkbox-group">
            <input
              type="checkbox"
              id="rememberMe"
              name="rememberMe"
              checked={formData.rememberMe}
              onChange={handleInputChange}
            />
            <label htmlFor="rememberMe">Remember my password</label>
          </div>
          
          <button 
            type="button" 
            className="forgot-password"
            onClick={startForgotPassword}
          >
            Forgot your password? 
          </button>
        </div>
        
        <button type="submit" className="submit-button">Login</button>
        
        <div className="switch-auth">
          Don't have an account?{' '}
          <button 
            type="button" 
            className="switch-button"
            onClick={() => handleTabChange('signup')}
          >
            Sign up
          </button>
        </div>
      </>
    );
  
    // Render forgot password form
    const renderForgotPassword = () => (
      <>
        <div className="forget">
          <h1>Password recovery</h1>
          <h2>Forget your password?</h2>
          <p>Enter your information to recreate a new password </p>
        </div>
        <div className="form-group">
          <input
            type="email"
            name="loginEmail"
            placeholder="Enter your startup's email"
            value={formData.loginEmail}
            onChange={handleInputChange}
            required
          />
        </div>
        
        <div className="button-group">
          <button 
            type="button" 
            className="back-button"
            onClick={backToLogin}
          >
            ← Back
          </button>
          <button 
            type="button" 
            className="submit-button"
            onClick={startEmailVerification}
          >
            Send 
          </button>
        </div>
      </>
    );
  
    // Render email verification form
    const renderEmailVerification = () => (
      <>
        <h1>Email verification</h1>
        <p>Enter the verification code sent to your email</p>
        
        <div className="verification-code-container">
          {verificationCode.map((digit, index) => (
            <input
              key={index}
              id={`verification-code-${index}`}
              type="text"
              maxLength="1"
              value={digit}
              onChange={(e) => handleVerificationCodeChange(e, index)}
              required
            />
          ))}
        </div>
        
        <div className="button-group">
          <button 
            type="button" 
            className="back-button"
            onClick={startForgotPassword}
          >
            ← Back
          </button>
          <button 
            type="button" 
            className="submit-button"
            onClick={startPasswordReset}
          >
            Verify
          </button>
        </div>
      </>
    );
  
    // Render password reset form
    const renderPasswordReset = () => (
      <>
        <h1>Password reset</h1>
        
        <div className="form-group">
          <input
            type="password"
            name="newPassword"
            placeholder="Enter your new password"
            value={formData.newPassword}
            onChange={handleInputChange}
            required
          />
        </div>
        
        <div className="form-group">
          <input
            type="password"
            name="confirmNewPassword"
            placeholder="Confirm your password"
            value={formData.confirmNewPassword}
            onChange={handleInputChange}
            required
          />
        </div>
        
        <div className="button-group">
          <button 
            type="button" 
            className="back-button"
            onClick={startEmailVerification}
          >
            ← Back
          </button>
          <button 
            type="button" 
            className="submit-button"
            onClick={backToLogin}
          >
            Reset Password
          </button>
        </div>
      </>
    );
  
    // Main render
    return (
      <div className="auth-container">
        {/* Navbar */}
        <div className="navbar">
          <div className="logo-container">
              <img src='logo.png' alt="Elev8 Logo" className="logo" />
            <span className="logo">Elev8</span>
            
          </div>
          <nav>
            <a href="#">Home</a>
            <a href="#">About us</a>
            <a href="#">Services</a>
            <a href="#">Blog</a>
            <a href="#">Contact us</a>
          </nav>
        </div>
  
        {/* Main content */}
        <div className="content-container">
          {/* Left form section */}
          <div className="form-section">
            {/* Tab navigation */}
            <div className="tab-navigation">
              <button
                className={`tab-button ${activeTab === 'signup' && authFlow === 'main' ? 'active' : ''}`}
                onClick={() => handleTabChange('signup')}
              >
                Sign up
              </button>
              <button
                className={`tab-button ${activeTab === 'login' && authFlow === 'main' ? 'active' : ''}`}
                onClick={() => handleTabChange('login')}
              >
                Login
              </button>
            </div>
  
            {/* Form content */}
            <form onSubmit={
              authFlow === 'main' ? 
                (activeTab === 'signup' ? handleSignupSubmit : handleLoginSubmit) :
              authFlow === 'forgot-password' ? handleForgotPasswordSubmit :
              authFlow === 'verify-email' ? handleVerifyEmailSubmit :
              handlePasswordResetSubmit
            }>
              {authFlow === 'main' ? (
                activeTab === 'signup' ? renderSignupStep() : renderLoginForm()
              ) : authFlow === 'forgot-password' ? (
                renderForgotPassword()
              ) : authFlow === 'verify-email' ? (
                renderEmailVerification()
              ) : (
                renderPasswordReset()
              )}
            </form>
          </div>
  
          {/* Right decorative section */}
          <div className="decorative-section">
            <div className="gradient-circle">
            <img src="photocircle.png" className="signup-image" />
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  export default AuthFlow;