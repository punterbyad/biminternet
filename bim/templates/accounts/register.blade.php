@extends('layouts.guest')

@section('title', 'Register')

@section('content')

    <!-- Content -->

    <div class="authentication-wrapper authentication-cover">
     </br></br>
      <!-- Logo -->

        <div class="authentication-inner row m-0">
            <!-- /Left Text -->
                <div class="d-none d-lg-flex col-lg-7 col-xl-8 align-items-center justify-content-center p-5 pb-2">
                    <img
                        src="img/illustrations/auth-register-illustration-light.png"
                        class="auth-cover-illustration w-100"
                        alt="auth-illustration"
                        data-app-light-img="illustrations/auth-register-illustration-light.png"
                        width="400"
                        height="600"
                        />
                    <img
                </div>
        </div>
        <!-- /Left Text -->

        <!-- Register -->
        <div class="d-flex col-12 col-lg-5 col-xl-4 align-items-center authentication-bg position-relative py-sm-5 px-4 py-4">
          <div class="w-px-400 mx-auto pt-5 pt-lg-0">
            <h4 class="mb-2">Adventure starts here 🚀</h4>
            <p class="mb-4">Make your hotspot management easy and fun!</p>

            <form id="formAuthentication" class="mb-3" action="{{ route('register') }}" method="POST">
                @csrf
              <div class="form-floating form-floating-outline mb-3">
                <input
                  type="text"
                  class="form-control"
                  id="name"
                  name="name"
                  required="required"
                  placeholder="Enter your Full name"
                  autofocus />
                <label for="name">Full Name</label>
              </div>
              <div class="form-floating form-floating-outline mb-3">
                <input type="tel" class="form-control" id="phone" name="phone" required="required" placeholder="Enter your phone number" />
                <label for="phone">Phone Number</label>
              </div>
              <div class="form-floating form-floating-outline mb-3">
                <input type="text" class="form-control" id="email" name="email" required="required" placeholder="Enter your email" />
                <label for="email">Email</label>
              </div>
              <div class="mb-3 form-password-toggle">
                <div class="input-group input-group-merge">
                  <div class="form-floating form-floating-outline">
                    <input
                      type="password"
                      id="password"
                      class="form-control"
                      name="password"
                      required="required"
                      placeholder="&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;"
                      aria-describedby="password" />
                    <label for="password">Password</label>
                  </div>
                  <span class="input-group-text cursor-pointer"><i class="mdi mdi-eye-off-outline"></i></span>
                </div>
              </div>
              <div class="mb-3 form-password-toggle">
                <div class="input-group input-group-merge">
                  <div class="form-floating form-floating-outline">
                    <input
                      type="password"
                      id="password_confirmation"
                      class="form-control"
                      name="password_confirmation"
                      required="required"
                      placeholder="&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;"
                      aria-describedby="password" />
                    <label for="password_confirmation">Confirm Password</label>
                  </div>
                  <span class="input-group-text cursor-pointer"><i class="mdi mdi-eye-off-outline"></i></span>
                </div>
              </div>

              <button class="btn btn-primary d-grid w-100">Sign up</button>
            </form>

            <p class="text-center mt-2">
              <span>Already have an account?</span>
              <a href="/login">
                <span>Sign in instead</span>
              </a>
            </p>

            <div class="divider my-4">
              <div class="divider-text">or</div>
            </div>

          </div>
        </div>
        <!-- /Register -->
      </div>

    <!-- / Content -->
@endsection

