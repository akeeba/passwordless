SET QUOTED_IDENTIFIER ON;

CREATE TABLE [#__webauthn_credentials]
(
  [id]         [NVARCHAR](1000) NOT NULL,
  [user_id]    [BIGINT]         NOT NULL DEFAULT 0,
  [credential] [NVARCHAR](max)  NOT NULL,
  [counter]    [BIGINT]         NOT NULL DEFAULT 0,
  CONSTRAINT "#__webauthn_credentials_id" UNIQUE NONCLUSTERED
    (
     "id" ASC
      ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY];

CREATE NONCLUSTERED INDEX "idx_#__webauthn_credentials_user_id" ON "#__webauthn_credentials"
  (
   "user_id" ASC
    ) WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF);


