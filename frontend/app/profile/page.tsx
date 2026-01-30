'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { authApi, User } from '@/lib/api';
import { startRegistration } from '@simplewebauthn/browser';

export default function ProfilePage() {
    const router = useRouter();
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [registering, setRegistering] = useState(false);
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
        setRegistering(true);

        try {
            // Step 1: Get options from server
            const options = await authApi.webauthn.registerOptions();

            // Step 2: Browser prompts for biometric
            const regResponse = await startRegistration(options);

            // Step 3: Send to server for verification
            const verifyRes = await authApi.webauthn.registerVerify(regResponse);

            if (verifyRes.success) {
                setMessage(verifyRes.message || 'Passkey registered successfully!');
            } else {
                setError('Verification failed. Please try again.');
            }
        } catch (err) {
            const errMsg = err instanceof Error ? err.message : 'Registration failed';
            // Handle user cancellation gracefully
            if (errMsg.includes('cancelled') || errMsg.includes('canceled') || errMsg.includes('NotAllowed')) {
                setError('Registration was cancelled.');
            } else {
                setError(errMsg);
            }
        } finally {
            setRegistering(false);
        }
    };

    const getRoleGradient = (role: string) => {
        switch (role) {
            case 'student': return 'gradient-student';
            case 'faculty': return 'gradient-faculty';
            case 'admin': return 'gradient-admin';
            default: return '';
        }
    };

    const getRoleColor = (role: string) => {
        switch (role) {
            case 'student': return 'text-blue-400';
            case 'faculty': return 'text-purple-400';
            case 'admin': return 'text-orange-400';
            default: return 'text-gray-400';
        }
    };

    const getBackLink = (role: string) => {
        switch (role) {
            case 'student': return '/student/vault';
            case 'faculty': return '/faculty/dashboard';
            case 'admin': return '/admin/dashboard';
            default: return '/';
        }
    };

    const handleLogout = () => {
        localStorage.clear();
        router.push('/');
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center gradient-bg">
                <div className="spinner" style={{ width: 40, height: 40 }} />
            </div>
        );
    }

    return (
        <div className={`min-h-screen gradient-bg ${getRoleGradient(user?.role || '')}`}>
            {/* Header */}
            <div className="max-w-4xl mx-auto px-6 py-8">
                <div className="flex items-center justify-between mb-8">
                    <Link href={getBackLink(user?.role || '')} className="text-gray-400 hover:text-white flex items-center gap-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                        </svg>
                        Back to Dashboard
                    </Link>
                    <button onClick={handleLogout} className="text-red-400 hover:text-red-300 text-sm">
                        Sign Out
                    </button>
                </div>

                {/* Profile Card */}
                <div className="card max-w-xl mx-auto">
                    {/* User Info */}
                    <div className="text-center pb-6 border-b border-gray-800">
                        <div className={`inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br ${user?.role === 'student' ? 'from-blue-500/20 to-blue-600/10' : user?.role === 'faculty' ? 'from-purple-500/20 to-purple-600/10' : 'from-orange-500/20 to-orange-600/10'} mb-4`}>
                            <span className="text-4xl">👤</span>
                        </div>
                        <h1 className="text-2xl font-bold text-white mb-2">{user?.username}</h1>
                        <span className={`inline-block px-3 py-1 rounded-full text-sm font-medium capitalize ${user?.role === 'student' ? 'bg-blue-500/10 text-blue-400' : user?.role === 'faculty' ? 'bg-purple-500/10 text-purple-400' : 'bg-orange-500/10 text-orange-400'}`}>
                            {user?.role}
                        </span>
                    </div>

                    {/* Passkeys Section */}
                    <div className="pt-6">
                        <h2 className="text-lg font-semibold mb-2 flex items-center gap-2">
                            <span className="text-xl">🔑</span>
                            Passkeys & Biometrics
                        </h2>
                        <p className="text-gray-400 text-sm mb-6">
                            Use your fingerprint, face, or device PIN to log in securely without a password.
                        </p>

                        {message && (
                            <div className="alert alert-success mb-4">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                                {message}
                            </div>
                        )}

                        {error && (
                            <div className="alert alert-error mb-4">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                {error}
                            </div>
                        )}

                        <button
                            onClick={registerPasskey}
                            disabled={registering}
                            className={`btn w-full ${user?.role === 'student' ? 'bg-blue-600 hover:bg-blue-700' : user?.role === 'faculty' ? 'bg-purple-600 hover:bg-purple-700' : 'bg-orange-600 hover:bg-orange-700'} text-white`}
                        >
                            {registering ? (
                                <span className="spinner" />
                            ) : (
                                <>
                                    <span className="mr-2">👆</span>
                                    Register New Passkey
                                </>
                            )}
                        </button>

                        {/* Info Box */}
                        <div className="mt-6 p-4 rounded-lg bg-gray-900/50 border border-gray-800">
                            <h3 className="text-sm font-medium text-gray-300 mb-2">How it works:</h3>
                            <ul className="text-xs text-gray-500 space-y-1">
                                <li>• Your device will prompt for biometric verification</li>
                                <li>• A unique cryptographic key is stored on your device</li>
                                <li>• Next time, just click "Sign in with Passkey" on the login page</li>
                                <li>• No password needed - just your fingerprint or face!</li>
                            </ul>
                        </div>
                    </div>
                </div>

                {/* Security Note */}
                <p className="text-center text-gray-600 text-xs mt-8">
                    🔒 Passkeys are more secure than passwords and can&apos;t be phished
                </p>
            </div>
        </div>
    );
}
