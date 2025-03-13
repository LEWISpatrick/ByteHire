/*
  Warnings:

  - You are about to drop the column `privateKeyAuthTag` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `privateKeyIV` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `privateKeySalt` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "privateKeyAuthTag",
DROP COLUMN "privateKeyIV",
DROP COLUMN "privateKeySalt";
