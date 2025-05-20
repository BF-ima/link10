import axios from 'axios';

const api = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  withCredentials: true,
});

export default api;

export const login = async (email, password) => {
  const response = await api.post('/login', { email, password });

  const accessToken = response.data.access; // or response.data.token
  localStorage.setItem('access', accessToken);

  // Set the token in default headers
  api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
};

//Make a call to your backend /refresh/ endpoint when the access token expires
export const refreshAccessToken = async () => {
  try {
    const response = await api.post('/refresh/'); // The cookie is automatically sent
    const newAccessToken = response.data.access;

    localStorage.setItem('access', newAccessToken);
    api.defaults.headers.common['Authorization'] = `Bearer ${newAccessToken}`;

    return newAccessToken;
  } catch (err) {
    console.error('Refresh token expired or invalid');
    return null;
  }
};

//catch expired tokens and refresh automatically
api.interceptors.response.use(
  response => response,
  async error => {
    const originalRequest = error.config;

    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const newToken = await refreshAccessToken();

      if (newToken) {
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        return api(originalRequest);
      }
    }

    return Promise.reject(error);
  }
);
