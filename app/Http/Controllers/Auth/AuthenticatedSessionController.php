<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Auth\Events\Verified;

class AuthenticatedSessionController extends Controller
{
    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response(['message' => __('auth.failed')], 422);
        }
        
        $token = auth()->user()->createToken('client-app');
        return ['token' => $token, 'user' => auth()->user()];;
    }

    /**
     * Handle an incoming authentication request with Google.
     */
    public function storeGoogle(Request $request)
    {
        DB::beginTransaction();

        try {
            $user = User::firstOrCreate(
                ['email' => $request->email],
                [
                    'name' => $request->name,
                    'password' => bcrypt(Str::random(16)),
                ]
            );

            if (!$user->hasVerifiedEmail()) {
                $user->markEmailAsVerified();
                event(new Verified($user));
            }

            Auth::login($user);

            DB::commit();

            return redirect()->intended('/');
        } catch (\Exception $e) {
            DB::rollBack();

            Log::error('Error in storeGoogle method: '.$e->getMessage());

            return redirect()->back()->withErrors(['error' => 'An error occurred while registering. Please try again.']);
        }
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): Response
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return response()->noContent();
    }
}
