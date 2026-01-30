'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { authApi, User } from '@/lib/api';
import { startRegistration } from '@simplewebauthn/browser';

export default function ProfilePage() {
    const router = useRouter();
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    useEffect(() => {
        fetchUser();
    }, []);

    const fetchUser = async () => {
        try {
            const res = await authApi.me();
            setUser(res.user);
        } catch (err) {
            router.push('/');
        } finally {
            setLoading(false);
        }
    };

    const registerPasskey = async () => {
        setMessage('');
        setError('');
        try {
            // Step 1: Get options
            const options = await authApi.webauthn.registerOptions();

            // Step 2: Browser interaction
            const regResponse = await startRegistration(options);

            // Step 3: Verify
            const verifyRes = await authApi.webauthn.registerVerify(regResponse);

            setMessage(verifyRes.message || 'Passkey registered!');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Registration failed');
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        router.push('/');
    };

    if (loading) return <div className="min-h-screen flex items-center justify-center text-white">Loading...</div>;

    return (
        <div className="min-h-screen gradient-bg p-8 text-white">
            <div className="w-full max-w-4xl mx-auto">
                <div className="flex justify-between items-center mb-10">
                    <h1 className="text-3xl font-bold">User Profile</h1>
                    <button onClick={logout} className="text-red-400 hover:text-red-300">
                        Sign Out
                    </button>
                </div>

                <div className="card max-w-lg mx-auto">
                    <div className="text-center mb-8">
                        <div className="text-4xl mb-4">👤</div>
                        <h2 className="text-2xl font-bold mb-2">{user?.username}</h2>
                        <span className="badge badge-primary capitalize">{user?.role}</span>
                    </div>

                    <div className="space-y-6">
                        <section className="border-t border-gray-800 pt-6">
                            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                                <span>🔑</span> Passkeys & Biometrics
                            </h3>
                            <p className="text-gray-400 text-sm mb-4">
                                Use your fingerprint, face, or device PIN to log in securely without a password.
                            </p>

                            {message && (
                                <div className="alert alert-success mb-4">
                                    <span>✓</span>
                                    <span>{message}</span>
                                </div>
                            )}

                            {error && (
                                <div className="alert alert-error mb-4">
                                    <span>⚠️</span>
                                    <span>{error}</span>
                                </div>
                            )}

                            <button
                                onClick={registerPasskey}
                                className="btn btn-outline w-full group"
                            >
                                <span className="group-hover:scale-110 transition-transform">👆</span>
                                Register New Passkey
                            </button>
                        </section>
                    </div>
                </div>
            </div>
        </div>
    );
}
