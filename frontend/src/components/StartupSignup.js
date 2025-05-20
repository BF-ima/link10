import React, { useState } from 'react';
import axios from 'axios';

const StartupSignup = () => {
  const [startupData, setStartupData] = useState({
    nom: '',
    genre_leader: '',
    date_naissance_leader: '',
    description: '',
    adresse: '',
    wilaya: '',
    email: '',
    numero_telephone: '',
    secteur: '',
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setStartupData({ ...startupData, [name]: value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    console.log('Submitting startup data:', startupData);
    
    axios
      .post('http://localhost:8000/api/startup/', startupData)
      .then((response) => {
        console.log('Success response:', response.data);
        alert('Startup created successfully');
      })
      .catch((error) => {
        console.error('Error details:', error.response ? error.response.data : error);
        alert('Error creating startup: ' + (error.response ? JSON.stringify(error.response.data) : error.message));
      });
  };
  return (
    <div>
      <h2>Signup a Startup</h2>
      <form onSubmit={handleSubmit}>
        <label>
          Nom:
          <input
            type="text"
            name="nom"
            value={startupData.nom}
            onChange={handleChange}
          />
        </label>
        <label>
          Genre Leader:
          <select
            name="genre_leader"
            value={startupData.genre_leader}
            onChange={handleChange}
          >
            <option value="Homme">Homme</option>
            <option value="Femme">Femme</option>
          </select>
        </label>
        <label>
          Date de Naissance Leader:
          <input
            type="date"
            name="date_naissance_leader"
            value={startupData.date_naissance_leader}
            onChange={handleChange}
          />
        </label>
        <label>
          Description:
          <textarea
            name="description"
            value={startupData.description}
            onChange={handleChange}
          />
        </label>
        <label>
          Adresse:
          <input
            type="text"
            name="adresse"
            value={startupData.adresse}
            onChange={handleChange}
          />
        </label>
        <label>
          Wilaya:
          <input
            type="text"
            name="wilaya"
            value={startupData.wilaya}
            onChange={handleChange}
          />
        </label>
        <label>
          Email:
          <input
            type="email"
            name="email"
            value={startupData.email}
            onChange={handleChange}
          />
        </label>
        <label>
          Numéro de Téléphone:
          <input
            type="text"
            name="numero_telephone"
            value={startupData.numero_telephone}
            onChange={handleChange}
          />
        </label>
        <label>
          Secteur:
          <select
            name="secteur"
            value={startupData.secteur}
            onChange={handleChange}
          >
            <option value="Tech">Technologie</option>
            <option value="Health">Santé</option>
            <option value="Finance">Finance</option>
          </select>
        </label>
        <button type="submit">Sign Up</button>
      </form>
    </div>
  );
};

export default StartupSignup;
