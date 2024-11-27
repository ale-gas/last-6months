import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  // State management with more descriptive variable names
  const [songs, setSongs] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [playlistCreated, setPlaylistCreated] = useState(false);

  // Configuration object for better maintainability
  const CONFIG = {
    CLIENT_ID: process.env.REACT_APP_SPOTIFY_CLIENT_ID || 'eb56e27d81c745179f5aca5e4f43a0bb',
    REDIRECT_URI: window.location.hostname === 'localhost' 
      ? 'http://localhost:3000/' 
      : 'https://ale-gas.github.io/last-6months/',
    SCOPES: 'user-library-read playlist-modify-private playlist-modify-public playlist-read-private'
  };

  // Centralized error handling utility
  const handleError = (error, customMessage = 'An unexpected error occurred') => {
    console.error(error);
    setError(customMessage);
    setIsLoading(false);
  };

  // Enhanced OAuth initiation with more robust random string generation
  const initiateOAuth = async () => {
    const generateCodeVerifier = (length) => {
      const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      return Array.from(crypto.getRandomValues(new Uint8Array(length)))
        .map(x => charset[x % charset.length])
        .join('');
    };

    try {
      const codeVerifier = generateCodeVerifier(64);
      const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
      const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hashed)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

      localStorage.setItem('code_verifier', codeVerifier);

      const authParams = new URLSearchParams({
        response_type: 'code',
        client_id: CONFIG.CLIENT_ID,
        scope: CONFIG.SCOPES,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge,
        redirect_uri: CONFIG.REDIRECT_URI,
      });

      window.location.href = `https://accounts.spotify.com/authorize?${authParams}`;
    } catch (error) {
      handleError(error, 'Authentication initialization failed');
    }
  };

  // Comprehensive token retrieval with improved error handling
  const getToken = async (code) => {
    try {
      const codeVerifier = localStorage.getItem('code_verifier');
      const response = await fetch('https://accounts.spotify.com/api/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: CONFIG.CLIENT_ID,
          grant_type: 'authorization_code',
          code,
          redirect_uri: CONFIG.REDIRECT_URI,
          code_verifier: codeVerifier,
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error_description || 'Token retrieval failed');

      const expiryTime = Date.now() + data.expires_in * 1000;
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('token_expiry', expiryTime);

      return data.access_token;
    } catch (error) {
      handleError(error, 'Failed to obtain access token');
      return null;
    }
  };

  // Refined song fetching with better error management
  const fetchLikedSongs = async (accessToken) => {
    setIsLoading(true);
    setError(null);

    try {
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

      const fetchPage = async (url) => {
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${accessToken}` }
        });

        if (!response.ok) throw new Error('Failed to fetch songs');
        return response.json();
      };

      let url = 'https://api.spotify.com/v1/me/tracks?limit=50';
      let allSongs = [];

      while (url) {
        const data = await fetchPage(url);
        const recentSongs = data.items.filter(item => 
          new Date(item.added_at) >= sixMonthsAgo
        );
        
        allSongs = [...allSongs, ...recentSongs];
        url = data.next;
      }

      setSongs(allSongs);
      setIsLoading(false);
    } catch (error) {
      handleError(error, 'Error fetching liked songs');
    }
  };

  // Playlist creation with improved chunk handling
  const createPlaylist = async (accessToken) => {
    setIsLoading(true);
    setError(null);

    try {
      const userResponse = await fetch('https://api.spotify.com/v1/me', {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const userData = await userResponse.json();

      const playlistResponse = await fetch(`https://api.spotify.com/v1/users/${userData.id}/playlists`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: 'last.6months',
          description: 'Playlist of songs added in the past 6 months',
          public: false
        })
      });

      const playlistData = await playlistResponse.json();
      if (!playlistResponse.ok) throw new Error(playlistData.error.message);

      const trackUris = songs.map(song => song.track.uri);
      const CHUNK_SIZE = 100;

      for (let i = 0; i < trackUris.length; i += CHUNK_SIZE) {
        const chunk = trackUris.slice(i, i + CHUNK_SIZE);
        await fetch(`https://api.spotify.com/v1/playlists/${playlistData.id}/tracks`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ uris: chunk })
        });
      }

      setPlaylistCreated(true);
      setIsLoading(false);
    } catch (error) {
      handleError(error, 'Playlist creation failed');
    }
  };

  // Unified authentication and song fetching logic
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const tokenExpiry = localStorage.getItem('token_expiry');

    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');

    if (accessToken && tokenExpiry && Date.now() < tokenExpiry) {
      fetchLikedSongs(accessToken);
    } else if (code) {
      getToken(code).then(token => {
        if (token) fetchLikedSongs(token);
      });
    } else {
      initiateOAuth();
    }
  }, []);

  return (
    <div className="App">
      <h1>last.6months</h1>
      {error && <p className="error-message">{error}</p>}
      
      {isLoading ? (
        <p>Loading...</p>
      ) : (
        songs.length > 0 && (
          <>
            <button onClick={() => createPlaylist(localStorage.getItem('access_token'))}>
              Create Playlist
            </button>
            {playlistCreated && (
              <p className="success-message">Playlist created successfully!</p>
            )}
          </>
        )
      )}

      <ul>
        {songs.map((song, index) => (
          <li key={index}>
            {song.track.name} - {song.track.artists.map(artist => artist.name).join(', ')}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
