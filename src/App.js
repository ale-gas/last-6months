import React, { useState, useEffect, useCallback } from 'react';
import './App.css';

// Configuration Constants
const CLIENT_ID = 'eb56e27d81c745179f5aca5e4f43a0bb';
const REDIRECT_URI = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? 'http://127.0.0.1:3000/' 
  : 'https://ale-gas.github.io/last-6months/';
const SCOPE = 'user-library-read playlist-modify-private playlist-modify-public playlist-read-private';
const AUTH_ENDPOINT = 'https://accounts.spotify.com/authorize';
const TOKEN_ENDPOINT = 'https://accounts.spotify.com/api/token';
const API_BASE = 'https://api.spotify.com/v1';

function App() {
  const [songs, setSongs] = useState([]);
  const [error, setError] = useState(null);
  const [playlistCreated, setPlaylistCreated] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [months, setMonths] = useState(6); // Default to 6 months

  // Helper: Generate Random String
  const generateRandomString = (length) => {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
  };

  // Helper: SHA-256
  const sha256 = async (plain) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
  };

  // Helper: Base64URL Encode
  const base64encode = (input) => {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  };

  // 1. Initiate OAuth
  const initiateOAuth = async () => {
    const codeVerifier = generateRandomString(64);
    const hashed = await sha256(codeVerifier);
    const codeChallenge = base64encode(hashed);
    const state = generateRandomString(16);

    window.localStorage.setItem('code_verifier', codeVerifier);
    window.localStorage.setItem('spotify_auth_state', state);

    const params = {
      response_type: 'code',
      client_id: CLIENT_ID,
      scope: SCOPE,
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      redirect_uri: REDIRECT_URI,
      state: state,
    };

    const authUrl = new URL(AUTH_ENDPOINT);
    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();
  };

  // 2. Exchange Token
  const getToken = useCallback(async (code) => {
    const codeVerifier = localStorage.getItem('code_verifier');
    localStorage.removeItem('code_verifier');

    const payload = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: codeVerifier,
      }),
    };

    try {
      const response = await fetch(TOKEN_ENDPOINT, payload);
      const data = await response.json();

      if (data.access_token) {
        const expiryTime = new Date().getTime() + data.expires_in * 1000; 
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('token_expiry', expiryTime);
        setIsLoggedIn(true);
        return data.access_token;
      } else {
        setError(data.error_description || 'Failed to obtain access token');
        return null;
      }
    } catch (error) {
      console.error('Token Error:', error);
      setError('Network error during authentication');
      return null;
    }
  }, []);

  // 3. Fetch Liked Songs (Optimized)
  const getLikedSongs = useCallback(async (accessToken, monthLimit) => {
    setIsLoading(true);
    setError(null);
    setPlaylistCreated(false); // Reset playlist status on new fetch

    const dateLimit = new Date();
    dateLimit.setMonth(dateLimit.getMonth() - monthLimit);

    let url = `${API_BASE}/me/tracks?limit=50`; 
    let fetchedSongs = [];
    let keepFetching = true;

    try {
      while (url && keepFetching) {
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });

        if (response.status === 401) {
          setError('Session expired. Please log in again.');
          setIsLoggedIn(false);
          localStorage.removeItem('access_token');
          setIsLoading(false);
          return;
        }

        if (response.status === 429) {
            const retryAfter = response.headers.get('Retry-After') || 1;
            console.warn(`Rate limited. Waiting ${retryAfter} seconds...`);
            await new Promise(r => setTimeout(r, retryAfter * 1000));
            continue; 
        }

        const data = await response.json();
        
        if (data.error) throw new Error(data.error.message);

        const validSongsInBatch = [];
        
        for (const item of data.items) {
          const addedDate = new Date(item.added_at);
          if (addedDate >= dateLimit) {
            validSongsInBatch.push(item);
          } else {
            keepFetching = false; 
          }
        }

        fetchedSongs = [...fetchedSongs, ...validSongsInBatch];
        url = keepFetching ? data.next : null;
      }

      setSongs(fetchedSongs);
    } catch (error) {
      console.error('Error fetching songs:', error);
      setError('Failed to fetch songs. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // 4. Create Playlist
  const createPlaylist = async (accessToken) => {
    setIsLoading(true);
    setError(null);
    try {
      const userResponse = await fetch(`${API_BASE}/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const userData = await userResponse.json();
      const userId = userData.id;

      const playlistResponse = await fetch(`${API_BASE}/users/${userId}/playlists`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: `last-${months}months`,
          description: `A playlist created from liked songs added in the past ${months} months.`,
          public: false,
        }),
      });

      if (!playlistResponse.ok) throw new Error('Failed to create playlist');

      const playlistData = await playlistResponse.json();
      const playlistId = playlistData.id;
        
      const trackUris = songs.map(song => song.track.uri).filter(uri => uri);

      if (trackUris.length > 0) {
        const batchSize = 100;
        for (let i = 0; i < trackUris.length; i += batchSize) {
          const batch = trackUris.slice(i, i + batchSize);
          
          const addTracksResponse = await fetch(`${API_BASE}/playlists/${playlistId}/tracks`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ uris: batch }),
          });

          if (!addTracksResponse.ok) throw new Error('Failed to add tracks');
        }
        setPlaylistCreated(true);
      } else {
        setError('No tracks found to add.');
      }
    } catch (error) {
      console.error('Error creating playlist:', error);
      setError('Failed to create playlist. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Effect: Check Auth and Fetch
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const tokenExpiry = localStorage.getItem('token_expiry');
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (accessToken && tokenExpiry && new Date().getTime() < tokenExpiry) {
      setIsLoggedIn(true);
      // Fetch songs whenever 'months' changes
      getLikedSongs(accessToken, months);
    } 
    else if (code) {
        const storedState = localStorage.getItem('spotify_auth_state');
        if (state === null || state !== storedState) {
            setError('State mismatch error. Authentication failed.');
            localStorage.removeItem('spotify_auth_state');
            return;
        }
        localStorage.removeItem('spotify_auth_state'); 
        window.history.pushState({}, null, '/'); 

        getToken(code).then(token => {
            if (token) getLikedSongs(token, months);
        });
    }
    else {
        localStorage.removeItem('access_token');
        localStorage.removeItem('token_expiry');
        setIsLoggedIn(false);
    }
  }, [getToken, getLikedSongs, months]); // Added 'months' dependency

  // Generate numbers 2 through 30 for the dropdown
  const monthOptions = Array.from({ length: 29 }, (_, i) => i + 2);

  return (
    <div className="App">
      <h1>last-6months</h1>
      
      {error && <p style={{ color: 'red', fontWeight: 'bold' }}>{error}</p>}
      
      {isLoading && <p className="loading-text">Loading...</p>}

      {!isLoggedIn && !isLoading && (
         <div className="button-container">
            <button onClick={initiateOAuth}>LOG IN TO SPOTIFY</button>
         </div>
      )}

      {isLoggedIn && !isLoading && (
        <>
          <p className="song-count-message">
            {songs.length} song{songs.length !== 1 ? 's' : ''} found from the last {months} months
          </p>
          
          <div className="playlist-button-container">
            {/* Month Selector Dropdown */}
            <select 
              className="month-selector"
              value={months} 
              onChange={(e) => setMonths(parseInt(e.target.value))}
            >
              {monthOptions.map(num => (
                <option key={num} value={num}>{num} Months</option>
              ))}
            </select>

            <button onClick={() => {
              const accessToken = localStorage.getItem('access_token');
              if (accessToken) createPlaylist(accessToken);
            }}>
              CREATE PLAYLIST
            </button>
          </div>
        </>
      )}

      {playlistCreated && <p className="congratulations-message">Congratulations! Playlist 'last-{months}months' created successfully.</p>}
      
      {songs.length > 0 && (
        <div className="song-list">
          {songs.map((song) => (
            <React.Fragment key={song.track.id || song.added_at}>
              <div className="song-name">
                {song.track.name} - {song.track.artists.map(artist => artist.name).join(', ')}
              </div>
              <div className="song-date">
                (Added on {new Date(song.added_at).toLocaleDateString()})
              </div>
            </React.Fragment>
          ))}
        </div>
      )} 
    </div>
  );
}

export default App;