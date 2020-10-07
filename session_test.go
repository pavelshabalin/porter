package porter

import (
	"log"
	"os"
	"testing"
	"time"
)

var testingLogger = log.New(os.Stdout, "", log.LstdFlags)

var blank = SessionIdentifier{
	SID:           "",
	SSID:          "",
	RemoteAddress: "",
}

type sp struct {
	save bool
	name string
}

func (s sp) ID() string {
	if s.save {
		return "Save session Enabled"
	}
	return "Save session Disabled"
}

func (s sp) CanLogin() bool {
	return true
}

func (s sp) AllowMultiLogin() bool {
	return true
}

func (s sp) SaveSession() bool {
	return s.save
}

var psSaveEnable = sp{save: true}
var psSaveDisable = sp{save: false}

func TestSession_Expired(t *testing.T) {
	type fields struct {
		ID             SessionIdentifier
		startTime      time.Time
		expirationTime time.Time
		refreshTime    time.Time
		Principal      AuthenticationPrincipal
	}
	type args struct {
		configuration *sessionConfiguration
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Expired + " + psSaveDisable.ID(),
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(-2 * time.Minute),
				time.Now(),
				psSaveDisable,
			},
			args: args{
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        true,
				},
			},
			want: true,
		},
		{
			name: "Expired + " + psSaveEnable.ID(),
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(-2 * time.Minute),
				time.Now(),
				psSaveEnable,
			},
			args: args{
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},
			},
			want: true,
		},
		{
			name: "NotExpired + " + psSaveEnable.ID(),
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(2 * time.Minute),
				time.Now(),
				psSaveEnable,
			},
			args: args{
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},
			},
			want: false,
		},

		{
			name: "Not expired Not Timeout + " + psSaveEnable.ID(),
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(2 * time.Minute),
				time.Now().Add(-1 * time.Minute),
				psSaveEnable,
			},
			args: args{
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},
			},
			want: false,
		},

		{
			name: "Not expired Timeout + " + psSaveEnable.ID(),
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(2 * time.Minute),
				time.Now().Add(-3 * time.Minute),
				psSaveEnable,
			},
			args: args{
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},
			},
			want: false,
		},

		{
			name: "Not expired Timeout + " + psSaveDisable.ID(),
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(2 * time.Minute),
				time.Now().Add(-3 * time.Minute),
				psSaveDisable,
			},
			args: args{
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				ID:             tt.fields.ID,
				startTime:      tt.fields.startTime,
				expirationTime: tt.fields.expirationTime,
				refreshTime:    tt.fields.refreshTime,
				Principal:      tt.fields.Principal,
			}
			if got := s.Expired(tt.args.configuration); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_Refresh(t *testing.T) {
	type fields struct {
		ID             SessionIdentifier
		startTime      time.Time
		expirationTime time.Time
		refreshTime    time.Time
		Principal      AuthenticationPrincipal
	}
	type args struct {
		refresh bool
		configuration *sessionConfiguration
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Timeout Refreshed",
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(2 * time.Minute),
				time.Now().Add(-3 * time.Minute),
				psSaveDisable,
			},
			args: args{
				true,
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},

			},
			want: false,
		},
		{
			name: "Timeout NoRefreshed",
			fields: fields{
				blank,
				time.Now().Add(-4 * time.Minute),
				time.Now().Add(2 * time.Minute),
				time.Now().Add(-4 * time.Minute),
				psSaveDisable,
			},
			args: args{
				false,
				&sessionConfiguration{
					Logger:             testingLogger,
					ExpirationDuration: 1 * time.Minute,
					Timeout:            2 * time.Minute,
					MultiLogin:         FailNew,
					ForceExpire:        false,
				},

			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					s := &Session{
						ID:             tt.fields.ID,
						startTime:      tt.fields.startTime,
						expirationTime: tt.fields.expirationTime,
						refreshTime:    tt.fields.refreshTime,
						Principal:      tt.fields.Principal,
					}
					if tt.args.refresh {
						s.Refresh()
					}
					if got := s.Expired(tt.args.configuration); got != tt.want {
						t.Errorf("Expired() = %v, want %v", got, tt.want)
					}
				})
			}
		})
	}
}
