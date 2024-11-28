import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [songs, setSongs] = useState([]);
  const [error, setError] = useState(null);
  const [playlistCreated, setPlaylistCreated] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Helper function to generate random string for PKCE
  const generateRandomString = (length) => {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
  };

  // Helper function to create SHA-256 hash
  const sha256 = async (plain) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
  };

  // Helper function to base64 encode
  const base64encode = (input) => {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  };

  // OAuth initiation function
  const initiateOAuth = async () => {
    const codeVerifier = generateRandomString(64);

    const hashed = await sha256(codeVerifier);
    const codeChallenge = base64encode(hashed);

    const clientId = 'eb56e27d81c745179f5aca5e4f43a0bb';
    const redirectUri = window.location.hostname === 'localhost' 
      ? 'http://localhost:3000/' 
      : 'https://ale-gas.github.io/last-6months/';
    const scope = 'user-library-read playlist-modify-private playlist-modify-public playlist-read-private';
    const authUrl = new URL("https://accounts.spotify.com/authorize");

    window.localStorage.setItem('code_verifier', codeVerifier);

    const params = {
      response_type: 'code',
      client_id: clientId,
      scope,
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      redirect_uri: redirectUri,
    };

    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();
  };

  // Token retrieval function
  const getToken = async (code) => {
    let codeVerifier = localStorage.getItem('code_verifier');
    const url = 'https://accounts.spotify.com/api/token';

    const payload = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: 'eb56e27d81c745179f5aca5e4f43a0bb',
        grant_type: 'authorization_code',
        code,
        redirect_uri: window.location.hostname === 'localhost' 
          ? 'http://localhost:3000/' 
          : 'https://ale-gas.github.io/last-6months/',
        code_verifier: codeVerifier,
      }),
    };

    try {
      const response = await fetch(url, payload);
      const data = await response.json();

      if (data.access_token) {
        console.log("Access Token Obtained:", data.access_token);
        // Store the token and its expiry time
        const expiryTime = new Date().getTime() + data.expires_in * 1000; 
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('token_expiry', expiryTime);
        return data.access_token;
      } else {
        console.error('Failed to obtain access token:', data);
        if (data.error && data.error_description) {
          setError(`Error: ${data.error} - ${data.error_description}`);
        } else {
          setError('Failed to obtain access token: Unknown error');
        }
        return null;
      }
    } catch (error) {
      console.error('Network or fetch error:', error);
      setError('Failed to obtain access token: Network or fetch error');
      return null;
    }
  };

  // Existing getLikedSongs function (unchanged from previous implementation)
  const getLikedSongs = async (accessToken) => {
    setIsLoading(true);
    setError(null);

    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    let url = 'https://api.spotify.com/v1/me/tracks?limit=50';
    let fetchedSongs = [];

    try {
      while (url) {
        const response = await fetch(url, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        });

        if (response.status === 401) {
          setError('Session expired. Please log in again.');
          setIsLoading(false);
          initiateOAuth();
          return;
        }

        const data = await response.json();
        if (data.error) {
          setError(`API Error: ${data.error.message}`);
          setIsLoading(false);
          return;
        }

        const filteredSongs = data.items.filter(item => {
          const addedDate = new Date(item.added_at);
          return addedDate >= sixMonthsAgo;
        });

        fetchedSongs = [...fetchedSongs, ...filteredSongs];
        url = data.next;
      }

      setSongs(fetchedSongs);
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching songs:', error);
      setError('Failed to fetch songs. Please try again.');
      setIsLoading(false);
    }
  };

  // Existing createPlaylist function (mostly unchanged)
  const createPlaylist = async (accessToken) => {
    setIsLoading(true);
    try {
      // Fetch user ID
      const userResponse = await fetch('https://api.spotify.com/v1/me', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      const userData = await userResponse.json();
      const userId = userData.id;

      // Create a new playlist
      const playlistResponse = await fetch(`https://api.spotify.com/v1/users/${userId}/playlists`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'last.6months',
          description: 'A playlist created from liked songs added in the past 6 months.',
          public: false,
        }),
      });

      const playlistData = await playlistResponse.json();

      if (playlistResponse.status === 201) {
        const playlistId = playlistData.id;
        const trackUris = songs.map(song => song.track.uri);

        // Add tracks to playlist
        await fetch(`https://api.spotify.com/v1/playlists/${playlistId}/tracks`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ uris: trackUris }),
        });

        setPlaylistCreated(true);
        setIsLoading(false);
      } else {
        throw new Error('Failed to create playlist');
      }
    } catch (error) {
      console.error('Error creating playlist:', error);
      setError('Failed to create playlist. Please try again.');
      setIsLoading(false);
    }
  };

  // UseEffect for initial authentication and song fetching
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const tokenExpiry = localStorage.getItem('token_expiry');

    if (accessToken && tokenExpiry && new Date().getTime() < tokenExpiry) {
      // Automatically fetch songs upon valid login
      getLikedSongs(accessToken);
    } else {
      // Re-authenticate if token is invalid or expired
      localStorage.removeItem('access_token');
      localStorage.removeItem('token_expiry');

      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');

      if (code) {
        getToken(code).then(token => {
          if (token) {
            getLikedSongs(token);
          }
        });
      } else {
        initiateOAuth();
      }
    }
  }, []);

  return (
    <div className="App">
      <h1>last.6months</h1>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {isLoading && <p className="loading-text">Loading...</p>}

      {!isLoading && songs.length > 0 && (
        <>
          <p className="song-count-message">
            {songs.length} song{songs.length !== 1 ? 's' : ''} found
          </p>
          <div className="playlist-button-container">
            <button onClick={() => {
              const accessToken = localStorage.getItem('access_token');
              if (accessToken) {
                createPlaylist(accessToken);
              } else {
                setError('Access token not available');
              }
            }}>
              CREATE PLAYLIST
            </button>
          </div>
        </>
      )}

      {playlistCreated && <p className="congratulations-message">Congratulations! Playlist created successfully.</p>}
      
      {songs.length > 0 && (
        <div className="song-list">
          {songs.map((song, index) => (
            <React.Fragment key={index}>
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
