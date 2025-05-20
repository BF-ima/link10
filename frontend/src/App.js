import React, { useState } from 'react';
import './App.css';
import LoginForm from './components/LoginForm';
import AuthFlow from './AuthFlow';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import StartupSignup from './components/StartupSignup';

const App = () => {
  const [showAuthFlow, setShowAuthFlow] = useState(true);

  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          {/* Add a default route */}
          <Route path="/" element={
            <>
              {showAuthFlow ? <AuthFlow /> : <LoginForm />}
              <button onClick={() => setShowAuthFlow(!showAuthFlow)}>
                Switch to {showAuthFlow ? 'Login Form' : 'Auth Flow'}
              </button>
            </>
          } />
          <Route path="/signup" element={<StartupSignup />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
};

export default App;



