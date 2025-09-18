@extends('layouts.app')

@section('content')
<div class="container">
    <h4 class="mb-4">Two-Factor Authentication</h4>
    <form method="POST" action="{{ route('otp.verify') }}">
        @csrf

        <div class="mb-3">
            <label for="otp" class="form-label">Enter OTP</label>
            <input id="otp" type="text" class="form-control @error('otp') is-invalid @enderror" name="otp" required autofocus>

            @error('otp')
                <div class="invalid-feedback">{{ $message }}</div>
            @enderror
        </div>

        <button type="submit" class="btn btn-primary">Verify</button>
    </form>
</div>
@endsection

