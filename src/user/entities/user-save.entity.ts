import {
  BaseEntity,
  Column,
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
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

  @Column({ type: 'bigint' })
  lastSaveTime: number;

  @ManyToOne(() => UserEntity, (user) => user.playerData)
  user: UserEntity;
}
