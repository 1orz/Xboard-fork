<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        if (!Schema::hasTable('v2_oauth_provider')) {
            Schema::create('v2_oauth_provider', function (Blueprint $table) {
                $table->integer('id', true);
                $table->string('identifier', 32)->unique();
                $table->string('name');
                $table->string('icon')->nullable();
                $table->string('client_id');
                $table->text('client_secret');
                $table->enum('discovery_mode', ['auto', 'manual'])->default('auto');
                $table->string('issuer')->nullable();
                $table->string('authorization_endpoint')->nullable();
                $table->string('token_endpoint')->nullable();
                $table->string('userinfo_endpoint')->nullable();
                $table->string('jwks_uri')->nullable();
                $table->string('scopes')->default('openid email profile');
                $table->string('sub_attribute')->default('sub');
                $table->string('email_attribute')->default('email');
                $table->string('name_attribute')->default('name');
                $table->string('email_verified_attribute')->default('email_verified');
                $table->boolean('allow_register')->default(false);
                $table->boolean('allow_bind')->default(true);
                $table->boolean('enable')->default(false);
                $table->integer('sort')->nullable();
                $table->integer('created_at');
                $table->integer('updated_at');
            });
        }

        if (!Schema::hasTable('v2_user_oauth_identity')) {
            Schema::create('v2_user_oauth_identity', function (Blueprint $table) {
                $table->integer('id', true);
                $table->integer('user_id');
                $table->integer('provider_id');
                $table->string('sub', 191);
                $table->string('email_snapshot')->nullable();
                $table->string('name_snapshot')->nullable();
                $table->text('raw_profile')->nullable();
                $table->integer('created_at');
                $table->integer('updated_at');
                $table->unique(['provider_id', 'sub'], 'uniq_provider_sub');
                $table->unique(['provider_id', 'user_id'], 'uniq_provider_user');
                $table->index('user_id');
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('v2_user_oauth_identity');
        Schema::dropIfExists('v2_oauth_provider');
    }
};
