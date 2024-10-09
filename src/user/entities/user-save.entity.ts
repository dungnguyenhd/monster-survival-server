import {
  BaseEntity,
  Column,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  DeleteDateColumn,
} from 'typeorm';
import { UserEntity } from './user.entity';
import { PlayerDataDto } from '../dto/user_request.dto';

@Entity('player_data')
export class PlayerDataEntity extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  userId: number;

  @Column({default: 0})
  hallLevel: number;

  @Column({default: 0})
  ranking: number;

  @Column({default: 0})
  currentDay: number;

  @Column('json')
  listPlacementData: PlayerDataDto['listPlacementData'];

  @Column('json')
  inventoryData: PlayerDataDto['inventoryData'];

  @Column('json')
  resources: PlayerDataDto['resources'];

  @Column('json')
  constructionCountData: PlayerDataDto['constructionCountData'];

  @Column({ type: 'bigint' })
  lastSaveTime: number;

  @Column({ type: 'bigint' })
  lastClaimDailyGemTime: number;

  @Column({ type: 'bigint' })
  lastClaimDailyChestTime: number;

  @DeleteDateColumn({ type: "datetime", nullable: true, default: null })
  deletedAt: Date;

  @ManyToOne(() => UserEntity, (user) => user.playerData)
  user: UserEntity;
}
