import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  // State management for the application
  const [songs, setSongs] = useState([]); // Stores liked songs
  const [error, setError] = useState(null); // Stores any error messages
  const [playlistCreated, setPlaylistCreated] = useState(false); // Tracks playlist creation status
  const [isLoading, setIsLoading] = useState(false); // Manages loading state

  // Helper function to generate a cryptographically secure random string
  // Used for PKCE (Proof Key for Code Exchange) in OAuth 2.0
  const generateRandomString = (length) => {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
  };

  // Create a SHA-256 hash of the code verifier
  // Part of the OAuth 2.0 PKCE flow for enhanced security
  const sha256 = async (plain) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
  };

  // Base64URL encode the hash
  // Ensures the code challenge is URL-safe
  const base64encode = (input) => {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  };

  // Initiate Spotify OAuth authorization process
  const initiateOAuth = async () => {
    // Generate a code verifier and challenge for PKCE
    const codeVerifier = generateRandomString(64);
    const hashed = await sha256(codeVerifier);
    const codeChallenge = base64encode(hashed);

    // Spotify app configuration
    const clientId = 'eb56e27d81c745179f5aca5e4f43a0bb';
    const redirectUri = window.location.hostname === 'localhost' 
      ? 'http://localhost:3000/' 
      : 'https://ale-gas.github.io/last-6months/';
    const scope = 'user-library-read playlist-modify-private playlist-modify-public playlist-read-private';
    
    const authUrl = new URL("https://accounts.spotify.com/authorize");

    // Store code verifier for token exchange later
    window.localStorage.setItem('code_verifier', codeVerifier);

    // Prepare authorization parameters
    const params = {
      response_type: 'code',
      client_id: clientId,
      scope,
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      redirect_uri: redirectUri,
    };

    // Redirect to Spotify authorization page
    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();
  };

  // Exchange authorization code for an access token
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
        // Store token with expiration time
        const expiryTime = new Date().getTime() + data.expires_in * 1000; 
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('token_expiry', expiryTime);
        return data.access_token;
      } else {
        // Handle token retrieval errors
        console.error('Failed to obtain access token:', data);
        setError(data.error_description || 'Failed to obtain access token');
        return null;
      }
    } catch (error) {
      console.error('Network or fetch error:', error);
      setError('Failed to obtain access token: Network error');
      return null;
    }
  };

  // Fetch liked songs from the last 6 months
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

        // Handle authentication errors
        if (response.status === 401) {
          setError('Session expired. Please log in again.');
          setIsLoading(false);
          initiateOAuth();
          return;
        }

        const data = await response.json();
        
        // Handle API errors
        if (data.error) {
          setError(`API Error: ${data.error.message}`);
          setIsLoading(false);
          return;
        }

        // Filter songs added in the last 6 months
        const filteredSongs = data.items.filter(item => {
          const addedDate = new Date(item.added_at);
          return addedDate >= sixMonthsAgo;
        });

        // Log filtered songs for debugging
        console.log('Filtered Songs:', filteredSongs.map(song => ({
          name: song.track.name,
          uri: song.track.uri,
          addedAt: song.added_at
        })));

        fetchedSongs = [...fetchedSongs, ...filteredSongs];
        url = data.next; // Pagination support
      }

      setSongs(fetchedSongs);
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching songs:', error);
      setError('Failed to fetch songs. Please try again.');
      setIsLoading(false);
    }
  };

  // Create a playlist with the liked songs
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
          name: 'last-6months',
          description: 'A playlist created from liked songs added in the past 6 months.',
          public: false,
        }),
      });

      const playlistData = await playlistResponse.json();

      if (playlistResponse.status === 201) {
        const playlistId = playlistData.id;
        
        // Extract valid track URIs
        const trackUris = songs
          .map(song => song.track.uri)
          .filter(uri => uri); // Remove any undefined URIs

        // Add tracks in batches (Spotify API limitation)
        if (trackUris.length > 0) {
          const batchSize = 100;
          for (let i = 0; i < trackUris.length; i += batchSize) {
            const batch = trackUris.slice(i, i + batchSize);
            
            const addTracksResponse = await fetch(`https://api.spotify.com/v1/playlists/${playlistId}/tracks`, {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ uris: batch }),
            });

            if (!addTracksResponse.ok) {
              const errorData = await addTracksResponse.json();
              console.error('Failed to add tracks:', errorData);
              throw new Error('Failed to add tracks to playlist');
            }
          }
        } else {
          console.warn('No tracks to add to the playlist');
          setError('No tracks found to add to the playlist');
          setIsLoading(false);
          return;
        }

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

  // Handle authentication and song fetching on component mount
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const tokenExpiry = localStorage.getItem('token_expiry');

    if (accessToken && tokenExpiry && new Date().getTime() < tokenExpiry) {
      // Use existing valid token to fetch songs
      getLikedSongs(accessToken);
    } else {
      // Clear expired token
      localStorage.removeItem('access_token');
      localStorage.removeItem('token_expiry');

      // Check for authorization code in URL
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');

      if (code) {
        // Exchange code for token and fetch songs
        getToken(code).then(token => {
          if (token) {
            getLikedSongs(token);
          }
        });
      } else {
        // Start OAuth flow
        initiateOAuth();
      }
    }
  }, []);

  // Render the application UI
  return (
    <div className="App">
      <h1>last-6months</h1>
      
      {/* Error handling */}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      
      {/* Loading indicator */}
      {isLoading && <p className="loading-text">Loading...</p>}

      {/* Song count and playlist creation button */}
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

      {/* Playlist creation success message */}
      {playlistCreated && <p className="congratulations-message">Congratulations! Playlist created successfully.</p>}
      
      {/* Song list display */}
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