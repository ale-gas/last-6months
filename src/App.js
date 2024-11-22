import React, { useState, useEffect } from 'react';
import './App.css';

//dev names were lasttest getpears inbasket

function App() {
  const [songs, setSongs] = useState([]);
  const [error, setError] = useState(null);
  const [playlistCreated, setPlaylistCreated] = useState(false); // Track playlist creation status
  const [showInBasket, setShowInBasket] = useState(false); // Track visibility of INBASKET button

  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const tokenExpiry = localStorage.getItem('token_expiry');

    if (accessToken && tokenExpiry && new Date().getTime() < tokenExpiry) {
      // Token is valid, fetch liked songs
      getLikedSongs(accessToken);
    } else {
      // Token is invalid or expired, clear it and re-authenticate
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

  const initiateOAuth = async () => {
    const generateRandomString = (length) => {
      const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      const values = crypto.getRandomValues(new Uint8Array(length));
      return values.reduce((acc, x) => acc + possible[x % possible.length], "");
    };

    const codeVerifier = generateRandomString(64);

    const sha256 = async (plain) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(plain);
      return window.crypto.subtle.digest('SHA-256', data);
    };

    const base64encode = (input) => {
      return btoa(String.fromCharCode(...new Uint8Array(input)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    };

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
        const expiryTime = new Date().getTime() + data.expires_in * 1000; // expires_in is in seconds
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
    }
  };

  const getLikedSongs = async (accessToken) => {
    console.log("Using Access Token:", accessToken);

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
          console.error('Access token expired or invalid');
          setError('Access token expired or invalid');
          return;
        }

        const data = await response.json();
        if (data.error) {
          console.error('API Error:', data.error);
          setError(data.error.message);
          return;
        }

        const filteredSongs = data.items.filter(item => {
          const addedDate = new Date(item.added_at);
          return addedDate >= sixMonthsAgo;
        });

        fetchedSongs = [...fetchedSongs, ...filteredSongs];
        url = data.next; // Get the next URL if there are more songs
      }

      setSongs(fetchedSongs);
      setShowInBasket(true); // Show the INBASKET button after fetching songs
    } catch (error) {
      console.error('Error fetching songs:', error);
      setError('Error fetching songs');
    }
  };

  const CHUNK_SIZE = 100; // Maximum number of tracks per request

const createPlaylist = async (accessToken) => {
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
      console.log('Playlist created successfully:', playlistData);

      // Extract playlist ID
      const playlistId = playlistData.id;
      const trackUris = songs.map(song => song.track.uri);

      if (trackUris.length === 0) {
        console.warn('No tracks to add to the playlist.');
        setError('No tracks to add to the playlist.');
        return;
      }

      // Function to add tracks to the playlist in chunks
      const addTracksInChunks = async (uris) => {
        for (let i = 0; i < uris.length; i += CHUNK_SIZE) {
          const chunk = uris.slice(i, i + CHUNK_SIZE);
          const addTracksResponse = await fetch(`https://api.spotify.com/v1/playlists/${playlistId}/tracks`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ uris: chunk }),
          });

          const addTracksData = await addTracksResponse.json();

          if (addTracksResponse.status !== 201) {
            console.error('Failed to add tracks to playlist:', addTracksData);
            if (addTracksData.error && addTracksData.error.message) {
              setError(`Error: ${addTracksData.error.message}`);
            } else {
              setError('Failed to add tracks to playlist: Unknown error');
            }
            return;
          }
        }

        setPlaylistCreated(true);
        setError(null); // Clear previous errors
      };

      // Add tracks in chunks
      await addTracksInChunks(trackUris);
    } else {
      console.error('Failed to create playlist:', playlistData);
      if (playlistData.error && playlistData.error.message) {
        setError(`Error: ${playlistData.error.message}`);
      } else {
        setError('Failed to create playlist: Unknown error');
      }
    }
  } catch (error) {
    console.error('Error creating playlist:', error);
    setError('Error creating playlist');
  }
};

return (
  <div className="App">
    <h1>last.6months</h1>
    {error && <p style={{ color: 'red' }}>{error}</p>}
    <div className="button-container">
      <button onClick={() => {
        const accessToken = localStorage.getItem('access_token');
        if (accessToken) {
          getLikedSongs(accessToken);
        } else {
          initiateOAuth();
        }
      }}>
        FETCH SONGS
      </button>
      {showInBasket && (
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
      )}
    </div>
    {playlistCreated && <p className="congratulations-message">Congratulations! Playlist created successfully.</p>}
    <ul>
      {songs.map((song, index) => (
        <li key={index}>
          {song.track.name} - {song.track.artists.map(artist => artist.name).join(', ')} (Added on {new Date(song.added_at).toLocaleDateString()})
        </li>
      ))}
    </ul>
  </div>
);

}

export default App;