<style scoped>
    .action-link {
        cursor: pointer;
    }
    .feedback, .invalid-feedback, .valid-feedback{
        margin-top: 0.25rem;
        font-size: 0.9rem;
    }
</style>

<template>
    <div>
        <div class="card card-default">
            <div class="card-header">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span>
                        Devices Access
                    </span>

                    <a class="action-link" tabindex="-1" @click="showActivateDeviceForm">
                        Activate New Device
                    </a>
                </div>
            </div>
            <div class="card-body">
                <!-- No Devices Notice -->
                <p class="mb-0" v-if="tokens.length === 0">
                    You have not activated any OAuth devices.
                </p>
                <!-- Devices -->
                <table class="table table-borderless mb-0" v-if="tokens.length > 0">
                    <thead>
                        <tr>
                            <th>Code</th>
                            <th>Scopes</th>
                            <th>Status</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="token in tokens">
                            <!-- Device Name -->
                            <td style="vertical-align: middle;">
                                {{ token.user_code || token.name }}
                            </td>
                            <!-- Scopes -->
                            <td style="vertical-align: middle;">
                                <span v-if="token.scopes.length > 0">
                                    {{ token.scopes.join(', ') }}
                                </span>
                            </td>
                            <!-- Status -->
                            <td style="vertical-align: middle;">
                                <span v-if="! token.name">
                                    pending
                                </span>
                                <span v-else>
                                    connected
                                </span>
                            </td>
                            <!-- Delete Button -->
                            <td style="vertical-align: middle; text-align: right;">
                                <a class="action-link text-danger" @click="revoke(token)">
                                    Delete
                                </a>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Activate Device Modal -->
        <div class="modal fade" id="modal-activate-device" tabindex="-1" role="dialog">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h4 class="modal-title">
                            Activate New Device
                        </h4>
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                    </div>
                    <div class="modal-body">
                        <!-- Form Errors -->
                        <div class="alert alert-danger" v-if="form.errors.length > 0">
                            <p class="mb-0"><strong>Whoops!</strong> Something went wrong!</p>
                            <br>
                            <ul>
                                <li v-for="error in form.errors">
                                    {{ error }}
                                </li>
                            </ul>
                        </div>
                        <!-- Activate device Form -->
                        <form role="form" @submit.prevent="activate">
                            <!-- User Code -->
                            <div class="form-group row">
                                <label class="col-md-3 col-form-label" for="user_code">User Code</label>
                                <div class="col-md-9">
                                    <input
                                        id="activate-device-user_code"
                                        v-on:keyup="checkUserCode"
                                        type="text" class="form-control"
                                        name="user_code"
                                        v-model="form.user_code"
                                        :class="{
                                            'is-valid': form.user_code && userCode.user_code,
                                            'is-invalid': form.user_code && userCode.error
                                        }"
                                    >
                                    <div v-if="! form.user_code || form.user_code.length < 8" class="feedback">
                                        Your device must display 8 digits code enter it here.
                                    </div>
                                    <div v-else-if="form.user_code && userCode.error" class="invalid-feedback">
                                        {{ userCode.error.message }}
                                    </div>
                                    <div v-else-if="form.user_code === userCode.user_code" class="valid-feedback">
                                        Device: {{ userCode.info }}
                                        <span v-if="userCode.scopes">
                                            <br>
                                            Scopes: {{ userCode.scopes }}
                                        </span>
                                    </div>
                                    <div v-else class="spinner-border spinner-border-sm text-light mt-3" role="status">
                                        <span class="sr-only">Loading...</span>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                    <!-- Modal Actions -->
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" @click="activate" v-if="userCode.user_code">
                            Activate
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
    export default {
        /*
         * The component's data.
         */
        data() {
            return {
                tokens: [],
                userCode: {},
                form: {
                    user_code: '',
                    errors: []
                }
            };
        },

        /**
         * Prepare the component (Vue 1.x).
         */
        ready() {
            this.prepareComponent();
        },

        /**
         * Prepare the component (Vue 2.x).
         */
        mounted() {
            this.prepareComponent();
        },

        methods: {
            /**
             * Prepare the component (Vue 2.x).
             */
            prepareComponent() {
                this.getTokens();
            },

            /**
             * Get all of the authorized tokens for the user.
             */
            getTokens() {
                axios.get('/oauth/device-tokens')
                        .then(response => {
                            this.tokens = response.data;
                        });
            },

            /**
             * Check if user code is valid.
             */
            checkUserCode: _.debounce(function() {
                this.userCode = {};

                if(this.form.user_code.length > 8) {
                    axios.post('/oauth/device-request', this.form)
                            .then((response) => {
                                this.userCode = response.data
                            })
                            .catch((error) => {
                                if(error.response.status === 429) {
                                    let epoch = error.response.headers['x-ratelimit-reset'];
                                    error.response.data.message += ` try again ${this.timeUntil(epoch)}`;
                                }
                                this.userCode = {
                                    error: error.response.data
                                };
                            });
                }
            }, 300, {
                'leading': true,
                'trailing': false
            }),

            /**
             * Activate device.
             */
            activate() {
                this.form.errors = [];

                axios.post('/oauth/device-tokens', this.form)
                        .then(response => {
                            this.userCode = {};
                            this.form.errors = [];
                            this.form.user_code = '';

                            this.tokens.push(response.data);
                            $('#modal-activate-device').modal('hide');
                        })
                        .catch(error => {
                            if (typeof error.response.data === 'object') {
                                this.form.errors = _.flatten(_.toArray(error.response.data.errors));
                            } else {
                                this.form.errors = ['Something went wrong. Please try again.'];
                            }
                        });
            },

            /**
             * Show the form for activating new device.
             */
            showActivateDeviceForm() {
                $('#modal-activate-device').modal('show');
            },

            /**
             * Revoke the given token.
             */
            revoke(token) {
                axios.delete('/oauth/device-tokens/' + token.id)
                        .then(response => {
                            this.getTokens();
                        });
            },

            /**
             * Format epoch for next try.
             */
            timeUntil(epoch) {
                const date = new Date(epoch * 1000);
                const seconds = Math.abs(Math.round((new Date() - date) / 1000));
                const minutes = Math.abs(Math.round(seconds / 60));
                if (seconds < 60) {
                    return `in ${ seconds } seconds`;
                } else if (seconds < 90) {
                    return 'in a minute';
                } else if (minutes < 60) {
                    return `in ${ minutes } minutes`;
                }
            },
        }
    }
</script>
