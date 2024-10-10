import {
  BaseEntity,
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { PlayerDataEntity } from './user-save.entity';

@Entity('user')
export class UserEntity extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    name: 'username',
    type: 'varchar',
    nullable: true,
    length: 255,
    unique: true,
  })
  username: string;

  @Column({ name: 'password', type: 'varchar', nullable: true, length: 255 })
  @Exclude()
  password: string;

  @Column({ name: 'displayName', type: 'varchar', nullable: true, length: 255 })
  display_name: string;

  @Column({ type: 'boolean', default: true })
  is_guest: boolean;

  @Column({ type: 'boolean', default: false })
  is_social: boolean;

  @Column({ type: 'varchar', default: 'england' })
  region: string;

  @Column()
  role: UserRole;

  @OneToOne(() => PlayerDataEntity, (playerData) => playerData.user, {
    cascade: true,
  })
  playerData: PlayerDataEntity;

  @DeleteDateColumn({ type: "datetime", nullable: true, default: null })
  deletedAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ type: 'datetime', nullable: false })
  @UpdateDateColumn()
  updatedAt: Date;
}

export enum UserRole {
  ADMIN,
  USER,
  DEVELOPER,
}
